//! # Token SDK Module (protobuf-only, deterministic)
//!
//! Protobuf-only encoding (prost::Message). No serde/JSON, no bincode.
//! Deterministic preimages are constructed manually for hashing.
//!
//! Replaces any JSON-based parameter parsing (e.g., locked balances) with
//! protobuf messages and removes any `bincode` serialization from preimages.

use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use dsm::{
    commitments::SmartCommitment as DsmSmartCommitment,
    core::identity::{verify_genesis_state, GenesisState},
    types::{
        error::DsmError,
        operations::{Operation, TransactionMode, VerificationType},
        state_types::State,
        token_types::{
            Balance, TokenMetadata, TokenOperation, TokenStatus, TokenSupply, TokenType,
        },
    },
};
use parking_lot::RwLock;
use prost::Message;

use super::{
    core_sdk::{CoreSDK, Operation as CoreOperation, TokenManagerTrait},
    counterparty_genesis_helpers::fetch_genesis_state,
    identity_sdk::IdentitySDK,
};

use crate::generated::{MetadataField, TokenMetadataProto};

// Replacing device_id with [u8; 32] for byte-first enforcement
type DevId = [u8; 32];

/// Token classification for balance lane routing.
/// dBTC keeps a dedicated lane because its locked supply is driven by withdrawal metadata.
/// ERA and user-created tokens follow the same canonical state/projection rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenLane {
    Dbtc,
    Canonical,
}

fn classify_token(token_id: &str) -> TokenLane {
    match token_id {
        "dBTC" => TokenLane::Dbtc,
        _ => TokenLane::Canonical,
    }
}

fn builtin_policy_anchor_uri(token_id: &str) -> Option<String> {
    crate::policy::builtin_policy_commit(token_id).map(|commit| {
        format!(
            "dsm:policy:{}",
            crate::util::text_id::encode_base32_crockford(&commit)
        )
    })
}

fn canonical_token_id_from_balance_key(token_key: &str) -> Option<&str> {
    match token_key {
        "ERA" => Some("ERA"),
        _ => token_key
            .split_once('|')
            .map(|(_, token_id)| token_id)
            .filter(|token_id| !token_id.is_empty()),
    }
}

fn encode_embedded_proof(public_key: &[u8], signature: &[u8]) -> Result<Vec<u8>, DsmError> {
    let pk_len = u16::try_from(public_key.len())
        .map_err(|_| DsmError::invalid_operation("public key too large for embedded proof"))?;
    let sig_len = u16::try_from(signature.len())
        .map_err(|_| DsmError::invalid_operation("signature too large for embedded proof"))?;

    let mut proof = Vec::with_capacity(4 + public_key.len() + signature.len());
    proof.extend_from_slice(&pk_len.to_le_bytes());
    proof.extend_from_slice(public_key);
    proof.extend_from_slice(&sig_len.to_le_bytes());
    proof.extend_from_slice(signature);
    Ok(proof)
}

// ---------- Protobuf wrappers for previously JSON’d or ad-hoc data ----------

/// Deterministic key/value for locked balances.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LockedBalanceEntry {
    /// key format: "{device_id}:{token_id}:{purpose}"
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(uint64, tag = "2")]
    pub amount: u64,
}

/// Locked balances container: deterministic repeated entries (sorted by key externally).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct LockedBalances {
    #[prost(message, repeated, tag = "1")]
    pub entries: ::prost::alloc::vec::Vec<LockedBalanceEntry>,
}

/// Canonical transfer record for history APIs.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransferRecord {
    #[prost(string, tag = "1")]
    pub token_id: String,
    #[prost(string, tag = "2")]
    pub from_device_id: String,
    #[prost(string, tag = "3")]
    pub to_device_id: String,
    #[prost(uint64, tag = "4")]
    pub amount: u64,
    #[prost(string, optional, tag = "5")]
    pub memo: Option<String>,
    #[prost(uint64, tag = "6")]
    pub state_number: u64,
    /// Deterministic logical ticks (no wall clock).
    #[prost(uint64, tag = "7")]
    pub tick: u64,
}

/// Local transport wrapper for token registry updates using repeated entries (deterministic)
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TokenRegistryUpdateList {
    #[prost(message, repeated, tag = "1")]
    pub items: ::prost::alloc::vec::Vec<TokenMetadataProto>,
}

// ---------- Helpers: domain <-> proto ----------

fn token_type_to_string(tt: &TokenType) -> String {
    match tt {
        TokenType::Native => "NATIVE",
        TokenType::Created => "CREATED",
        TokenType::Restricted => "RESTRICTED",
        TokenType::Wrapped => "WRAPPED",
    }
    .to_string()
}

fn token_type_from_string(s: &str) -> TokenType {
    match s.to_uppercase().as_str() {
        "NATIVE" => TokenType::Native,
        "CREATED" => TokenType::Created,
        "RESTRICTED" => TokenType::Restricted,
        "WRAPPED" => TokenType::Wrapped,
        _ => TokenType::Created,
    }
}

fn token_metadata_to_proto(m: &TokenMetadata) -> TokenMetadataProto {
    TokenMetadataProto {
        token_id: m.token_id.clone(),
        name: m.name.clone(),
        symbol: m.symbol.clone(),
        description: m.description.clone(),
        icon_url: m.icon_url.clone(),
        decimals: m.decimals as u32,
        token_type: token_type_to_string(&m.token_type),
        owner_id: crate::util::text_id::encode_base32_crockford(&m.owner_id),
        // bridge tick -> index (deterministic)
        creation_index: m.creation_tick,
        metadata_uri: m.metadata_uri.clone(),
        policy_anchor: m.policy_anchor.clone(),
        fields: map_to_metadata_fields(&m.fields),
    }
}

fn token_metadata_from_proto(p: &TokenMetadataProto) -> TokenMetadata {
    TokenMetadata {
        token_id: p.token_id.clone(),
        name: p.name.clone(),
        symbol: p.symbol.clone(),
        description: p.description.clone().filter(|s| !s.is_empty()),
        icon_url: p.icon_url.clone().filter(|s| !s.is_empty()),
        decimals: (p.decimals as u8).min(18),
        token_type: token_type_from_string(&p.token_type),
        owner_id: {
            let bytes =
                crate::util::text_id::decode_base32_crockford(&p.owner_id).unwrap_or_default();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        },
        creation_tick: p.creation_index,
        metadata_uri: p.metadata_uri.clone().filter(|s| !s.is_empty()),
        policy_anchor: p.policy_anchor.clone().filter(|s| !s.is_empty()),
        fields: metadata_fields_to_map(&p.fields),
    }
}

/// Convert map<string,string> to repeated MetadataField (deterministic order by key)
fn map_to_metadata_fields(m: &HashMap<String, String>) -> Vec<MetadataField> {
    let mut entries: Vec<(String, String)> =
        m.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
        .into_iter()
        .map(|(key, value)| MetadataField { key, value })
        .collect()
}

/// Convert repeated MetadataField to map<string,string>
fn metadata_fields_to_map(v: &Vec<MetadataField>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for mf in v {
        out.insert(mf.key.clone(), mf.value.clone());
    }
    out
}

fn encode_registry_update(map: &HashMap<String, TokenMetadata>) -> Result<Vec<u8>, DsmError> {
    let mut items: Vec<TokenMetadataProto> = Vec::with_capacity(map.len());
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for k in keys {
        if let Some(v) = map.get(k) {
            items.push(token_metadata_to_proto(v));
        }
    }
    let msg = TokenRegistryUpdateList { items };
    Ok(msg.encode_to_vec())
}

fn decode_registry_update(bytes: &[u8]) -> Result<HashMap<String, TokenMetadata>, DsmError> {
    let reg = TokenRegistryUpdateList::decode(bytes).map_err(|e| {
        DsmError::serialization_error(
            "Failed to decode TokenRegistryUpdateList",
            "Failed to decode token registry update",
            None::<String>,
            Some(e),
        )
    })?;
    let mut out = HashMap::new();
    for v in reg.items {
        let m = token_metadata_from_proto(&v);
        out.insert(m.token_id.clone(), m);
    }
    Ok(out)
}

// ---------- Genesis state cache for offline verification of counterparties ----------

#[derive(Clone)]
pub struct GenesisStateCache {
    /// Cached Genesis states by device ID
    genesis_states: Arc<RwLock<HashMap<String, GenesisState>>>,
    /// Track which Genesis states have been verified
    verified_states: Arc<RwLock<HashMap<String, bool>>>,
}

// ---------- Create-token parameters ----------

#[derive(Debug, Clone)]
pub struct CreateTokenParams {
    pub authorized_by: String,
    pub proof: Vec<u8>,
    pub identity_data: Vec<u8>,
    pub metadata: HashMap<String, Vec<u8>>,
    pub commitment: Vec<u8>,
}

// ---------- ERA token ----------

#[derive(Debug, Clone)]
pub struct EraToken {
    pub token_id: String,
    pub metadata: TokenMetadata,
    pub status: TokenStatus,
    pub total_supply: Balance,
    pub circulating_supply: Balance,
    pub fee_schedule: HashMap<String, Balance>,
}

impl EraToken {
    pub fn new(total_supply: u64) -> Self {
        let mut fields = HashMap::new();
        fields.insert("ecosystem".to_string(), "DSM".to_string());
        fields.insert("governance_model".to_string(), "meritocratic".to_string());
        fields.insert("version".to_string(), "1.0".to_string());
        fields.insert("token_standard".to_string(), "DSM-20".to_string());

        let mut fee_schedule = HashMap::new();
        fee_schedule.insert(
            "token_creation".to_string(),
            Balance::from_state(10, [0u8; 32], 0),
        );
        fee_schedule.insert("token_update".to_string(), Balance::zero());
        fee_schedule.insert("token_transfer".to_string(), Balance::zero());
        fee_schedule.insert("token_burn".to_string(), Balance::zero());
        fee_schedule.insert("subscription_base".to_string(), Balance::zero());
        fee_schedule.insert("state_transition".to_string(), Balance::zero());
        fee_schedule.insert(
            "smart_commitment".to_string(),
            Balance::from_state(2, [0u8; 32], 0),
        );
        fee_schedule.insert(
            "storage_tier_1gb".to_string(),
            Balance::from_state(5, [0u8; 32], 0),
        );
        fee_schedule.insert(
            "storage_tier_10gb".to_string(),
            Balance::from_state(25, [0u8; 32], 0),
        );
        fee_schedule.insert(
            "storage_tier_100gb".to_string(),
            Balance::from_state(100, [0u8; 32], 0),
        );
        fee_schedule.insert(
            "storage_tier_1tb".to_string(),
            Balance::from_state(500, [0u8; 32], 0),
        );
        fee_schedule.insert(
            "storage_tier_unlimited".to_string(),
            Balance::from_state(2000, [0u8; 32], 0),
        );

        let metadata = TokenMetadata {
            name: "ERA".to_string(),
            symbol: "ERA".to_string(),
            description: Some("Resilient Oracle-Optimized Trustless token - the native token of the DSM ecosystem".to_string()),
            icon_url: None,
            decimals: 18,
            fields,
            token_id: "ERA".to_string(),
            token_type: TokenType::Native,
            owner_id: *dsm::crypto::blake3::domain_hash("DSM/system-owner", b"").as_bytes(),
            creation_tick: crate::util::deterministic_time::tick(),
            metadata_uri: Some("ipfs://QmTokenMetadataHash".to_string()),
            policy_anchor: builtin_policy_anchor_uri("ERA"),
        };

        Self {
            token_id: "ERA".to_string(),
            metadata,
            status: TokenStatus::Active,
            total_supply: Balance::from_state(total_supply, [0u8; 32], 0),
            circulating_supply: Balance::zero(),
            fee_schedule,
        }
    }

    pub fn get_fee(&self, operation_type: &str) -> Balance {
        self.fee_schedule
            .get(operation_type)
            .cloned()
            .unwrap_or(Balance::from_state(1, [0u8; 32], 0))
    }

    pub fn update_fee_schedule(&mut self, new_schedule: HashMap<String, Balance>) {
        self.fee_schedule = new_schedule;
    }
}

// ---------- Token SDK ----------

pub struct TokenSDK<I: Send + Sync> {
    core_sdk: Arc<CoreSDK>,
    token_metadata: Arc<RwLock<HashMap<String, TokenMetadata>>>,
    era_token: Arc<RwLock<EraToken>>,
    balances: Arc<RwLock<HashMap<DevId, HashMap<String, Balance>>>>,
    transaction_history: Arc<RwLock<Vec<(TokenOperation, u64)>>>,
    /// Canonical device identifier (binary) for balance ownership & metadata defaults.
    device_id: [u8; 32],
    /// Device SPHINCS+ secret key used to sign transfer operations before submission.
    signing_key: Arc<RwLock<Option<Vec<u8>>>>,
    _phantom: PhantomData<I>,
    genesis_state_cache: GenesisStateCache,
}

impl<I: Send + Sync> TokenSDK<I> {
    fn convert_to_core_operation(dsm_op: Operation) -> CoreOperation {
        match dsm_op {
            Operation::Generic {
                operation_type,
                data,
                message,
                ..
            } => CoreOperation::Generic {
                operation_type: String::from_utf8_lossy(&operation_type).into_owned(),
                data,
                message,
            },
            Operation::Transfer {
                amount,
                token_id,
                recipient,
                ..
            } => CoreOperation::Transfer {
                token_id: token_id.clone(),
                recipient: recipient.clone(),
                amount: amount.value(),
            },
            _ => CoreOperation::Generic {
                operation_type: "generic".to_string(),
                data: vec![],
                message: "Converted operation".to_string(),
            },
        }
    }

    fn find_token_metadata_state(&self, token_id: &str) -> Result<State, DsmError> {
        let current_state = self.core_sdk.get_current_state()?;
        let max_state_number = current_state.state_number;

        for state_number in (0..=max_state_number).rev() {
            if let Ok(state) = self.core_sdk.get_state_by_number(state_number) {
                match &state.operation {
                    Operation::Create { metadata, .. } => {
                        if !metadata.is_empty() {
                            if let Ok(proto) = TokenMetadataProto::decode(metadata.as_slice()) {
                                if proto.token_id == token_id || proto.symbol == token_id {
                                    return Ok(state.clone());
                                }
                            }
                        }
                    }
                    Operation::Generic {
                        operation_type,
                        data,
                        ..
                    } => {
                        if operation_type.as_slice() == b"token_create"
                            || operation_type.as_slice() == b"token_registry_update"
                        {
                            if let Ok(registry_update) = decode_registry_update(data) {
                                if registry_update.contains_key(token_id) {
                                    return Ok(state.clone());
                                }
                            } else if let Ok(single) = TokenMetadataProto::decode(data.as_slice()) {
                                if single.token_id == token_id || single.symbol == token_id {
                                    return Ok(state.clone());
                                }
                            }
                        }
                    }
                    _ => continue,
                }
            }
        }

        Err(DsmError::state("Token metadata not found in the chain"))
    }

    fn metadata_for_token_from_state(
        &self,
        state: &State,
        token_id: &str,
    ) -> Option<TokenMetadata> {
        match &state.operation {
            Operation::Generic { data, .. } => {
                if let Ok(registry_update) = decode_registry_update(data) {
                    return registry_update.get(token_id).cloned();
                }
                if let Ok(single) = TokenMetadataProto::decode(data.as_slice()) {
                    let metadata = token_metadata_from_proto(&single);
                    if metadata.token_id == token_id || metadata.symbol == token_id {
                        return Some(metadata);
                    }
                }
                None
            }
            Operation::Create { metadata, .. } => {
                if let Ok(proto) = TokenMetadataProto::decode(metadata.as_slice()) {
                    let metadata = token_metadata_from_proto(&proto);
                    if metadata.token_id == token_id || metadata.symbol == token_id {
                        return Some(metadata);
                    }
                }
                None
            }
            _ => None,
        }
    }

    pub(crate) fn resolve_policy_commit_strict(
        &self,
        token_id: &str,
    ) -> Result<[u8; 32], DsmError> {
        if let Some(commit) = crate::policy::builtin_policy_commit(token_id) {
            return Ok(commit);
        }

        {
            let metadata = self.token_metadata.read();
            if let Some(token_metadata) = metadata.get(token_id) {
                return crate::policy::strict_policy_commit_for_token(
                    token_id,
                    token_metadata.policy_anchor.as_deref(),
                );
            }
        }

        let state = self.find_token_metadata_state(token_id)?;
        let token_metadata = self
            .metadata_for_token_from_state(&state, token_id)
            .ok_or_else(|| {
                DsmError::state(format!(
                    "Token metadata state for {token_id} did not contain canonical metadata"
                ))
            })?;

        crate::policy::strict_policy_commit_for_token(
            token_id,
            token_metadata.policy_anchor.as_deref(),
        )
    }

    fn builtin_era_metadata(&self) -> TokenMetadata {
        let mut metadata = self.era_token.read().metadata.clone();
        metadata.policy_anchor = builtin_policy_anchor_uri("ERA");
        metadata
    }

    fn builtin_token_metadata(&self, token_id: &str) -> Option<TokenMetadata> {
        match token_id {
            "ERA" => Some(self.builtin_era_metadata()),
            crate::sdk::bitcoin_tap_sdk::DBTC_TOKEN_ID => Some(
                crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk::dbtc_token_metadata(self.device_id),
            ),
            _ => None,
        }
    }

    fn sync_projection_from_state(
        &self,
        device_id: &[u8; 32],
        state: &State,
        token_id: &str,
        policy_commit: &[u8; 32],
        balance: &Balance,
    ) {
        let device_id_txt = crate::util::text_id::encode_base32_crockford(device_id);
        let state_hash = match state.hash() {
            Ok(hash) => hash,
            Err(e) => {
                log::warn!(
                    "[TokenSDK] Failed to compute state hash while syncing projection for {}: {}",
                    token_id,
                    e
                );
                return;
            }
        };

        let record = crate::storage::client_db::BalanceProjectionRecord {
            balance_key: dsm::core::token::derive_canonical_balance_key(
                policy_commit,
                &state.device_info.public_key,
                token_id,
            ),
            device_id: device_id_txt,
            token_id: token_id.to_string(),
            policy_commit: crate::util::text_id::encode_base32_crockford(policy_commit),
            available: balance.available(),
            locked: balance.locked(),
            source_state_hash: crate::util::text_id::encode_base32_crockford(&state_hash),
            source_state_number: state.state_number,
            updated_at: crate::util::deterministic_time::tick(),
        };

        if let Err(e) = crate::storage::client_db::upsert_balance_projection(&record) {
            log::warn!(
                "[TokenSDK] Failed to sync projection row for {}: {}",
                token_id,
                e
            );
        }
    }

    fn read_projected_balance(&self, device_id: &[u8; 32], token_id: &str) -> Option<Balance> {
        let state = self.core_sdk.get_current_state().ok()?;
        let policy_commit = self.resolve_policy_commit_strict(token_id).ok()?;
        let canonical = dsm::core::token::derive_canonical_balance_key(
            &policy_commit,
            &state.device_info.public_key,
            token_id,
        );
        let device_id_txt = crate::util::text_id::encode_base32_crockford(device_id);
        let policy_commit_txt = crate::util::text_id::encode_base32_crockford(&policy_commit);

        if let Some(balance) = state.token_balances.get(&canonical).cloned() {
            self.sync_projection_from_state(device_id, &state, token_id, &policy_commit, &balance);
            return Some(balance);
        }

        match crate::storage::client_db::get_validated_balance_projection(
            &device_id_txt,
            token_id,
            &canonical,
            &policy_commit_txt,
        ) {
            Ok(Some(record)) => {
                let state_hash =
                    crate::util::text_id::decode_base32_crockford(&record.source_state_hash)
                        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
                        .unwrap_or_else(|| state.hash().unwrap_or([0u8; 32]));
                let mut balance =
                    Balance::from_state(record.available, state_hash, record.source_state_number);
                if record.locked > 0 {
                    let _ = balance.lock(record.locked);
                }
                return Some(balance);
            }
            Ok(None) => {}
            Err(e) => {
                log::warn!(
                    "[TokenSDK] Ignoring invalid projection row for {}: {}",
                    token_id,
                    e
                );
            }
        }

        None
    }

    pub(crate) fn project_balance_cache_from_state(
        &self,
        device_id: DevId,
        state: &State,
    ) -> Result<(), DsmError> {
        if state.device_info.device_id != device_id {
            return Err(DsmError::invalid_operation(
                "canonical projection device mismatch",
            ));
        }

        let mut projected = HashMap::new();
        for (token_key, balance) in &state.token_balances {
            let Some(token_id) = canonical_token_id_from_balance_key(token_key) else {
                continue;
            };
            if token_id == "BTC_CHAIN" {
                continue;
            }
            projected.insert(token_id.to_string(), balance.clone());
        }

        let mut balances = self.balances.write();
        let refreshed = balances
            .get(&device_id)
            .map(|existing| existing != &projected)
            .unwrap_or(!projected.is_empty());
        if refreshed {
            log::info!(
                "[TokenSDK] canonical projection refreshed local cache for {} at state #{}",
                crate::util::text_id::encode_base32_crockford(&device_id),
                state.state_number,
            );
        }
        balances.insert(device_id, projected);
        Ok(())
    }

    fn cache_token_metadata_strict(
        &self,
        mut metadata: TokenMetadata,
    ) -> Result<TokenMetadata, DsmError> {
        if let Some(policy_anchor) = builtin_policy_anchor_uri(&metadata.token_id) {
            metadata.policy_anchor = Some(policy_anchor);
        }

        crate::policy::strict_policy_commit_for_token(
            &metadata.token_id,
            metadata.policy_anchor.as_deref(),
        )?;

        self.token_metadata
            .write()
            .insert(metadata.token_id.clone(), metadata.clone());

        Ok(metadata)
    }

    fn resolve_token_metadata_strict(
        &self,
        token_id: &str,
    ) -> Result<Option<TokenMetadata>, DsmError> {
        if let Some(metadata) = self.builtin_token_metadata(token_id) {
            return self.cache_token_metadata_strict(metadata).map(Some);
        }

        if let Some(token_metadata) = self.token_metadata.read().get(token_id).cloned() {
            return self.cache_token_metadata_strict(token_metadata).map(Some);
        }

        let state = match self.find_token_metadata_state(token_id) {
            Ok(state) => state,
            Err(_) => return Ok(None),
        };
        let token_metadata = self
            .metadata_for_token_from_state(&state, token_id)
            .ok_or_else(|| {
                DsmError::state(format!(
                    "Token metadata state for {token_id} did not contain canonical metadata"
                ))
            })?;

        self.cache_token_metadata_strict(token_metadata).map(Some)
    }

    pub fn new(core_sdk: Arc<CoreSDK>, device_id: [u8; 32]) -> Self {
        use std::sync::OnceLock;
        static MIGRATION_DONE: OnceLock<()> = OnceLock::new();

        let era = EraToken::new(1_000_000_000); // 1 billion units

        // Run stale-key migration exactly once per process
        MIGRATION_DONE.get_or_init(|| {
            core_sdk.migrate_token_balance_keys();
        });

        Self {
            core_sdk,
            token_metadata: Arc::new(RwLock::new(HashMap::new())),
            era_token: Arc::new(RwLock::new(era)),
            balances: Arc::new(RwLock::new(HashMap::new())),
            transaction_history: Arc::new(RwLock::new(Vec::new())),
            device_id,
            signing_key: Arc::new(RwLock::new(None)),
            _phantom: PhantomData,
            genesis_state_cache: GenesisStateCache::new(),
        }
    }

    /// Inject the device's SPHINCS+ secret key so transfers can be signed before
    /// reaching the state machine.
    pub fn set_signing_key(&self, secret_key: Vec<u8>) {
        *self.signing_key.write() = Some(secret_key);
    }

    /// Sign a transfer operation by clearing the signature field and applying the
    /// device's SPHINCS+ secret key. Returns a descriptive error if the key has
    /// not been registered yet.
    ///
    /// RETIRED: Use sign_transfer_canonical_v3() for online transfers to ensure
    /// sender and receiver use identical signing preimages.
    fn sign_transfer_operation(&self, op: &Operation) -> Result<Vec<u8>, DsmError> {
        let signing_key = self.signing_key.read().as_ref().cloned().ok_or_else(|| {
            DsmError::unauthorized(
                "Signing key not initialized for TokenSDK transfers",
                None::<std::io::Error>,
            )
        })?;

        let mut op_clone = op.clone();
        if let Operation::Transfer { signature, .. } = &mut op_clone {
            signature.clear();
        } else {
            return Err(DsmError::invalid_operation(
                "Attempted to sign a non-transfer operation",
            ));
        }

        let payload = op_clone.to_bytes();
        dsm::crypto::sphincs::sphincs_sign(&signing_key, &payload).map_err(|e| {
            DsmError::crypto(
                format!("Failed to sign transfer operation: {e}"),
                None::<std::io::Error>,
            )
        })
    }

    /// Sign a transfer using the canonical v3 signing preimage.
    /// This MUST be used for online transfers to ensure sender and receiver
    /// verify the exact same bytes (AF-2 remediation).
    ///
    /// All parameters are raw bytes (not base32-encoded) to ensure deterministic
    /// encoding without format conversion bugs.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_transfer_canonical_v3(
        &self,
        from_device_id: &[u8; 32],
        to_device_id: &[u8; 32],
        token_id: &str,
        amount: u64,
        chain_tip: &[u8; 32],
        seq: u64,
        nonce: &[u8],
        memo: &str,
    ) -> Result<Vec<u8>, DsmError> {
        let signing_key = self.signing_key.read().as_ref().cloned().ok_or_else(|| {
            DsmError::unauthorized(
                "Signing key not initialized for TokenSDK transfers",
                None::<std::io::Error>,
            )
        })?;

        // Compute canonical signing preimage (same function receiver uses to verify)
        let signing_bytes = dsm::envelope::compute_transfer_signing_bytes_v3(
            from_device_id,
            to_device_id,
            token_id,
            amount,
            chain_tip,
            seq,
            nonce,
            memo,
        );

        // Diagnostic: log preimage hash for debugging sender/receiver mismatch
        let preimage_hash =
            dsm::crypto::blake3::domain_hash("DSM/signing-preimage", &signing_bytes);
        log::info!(
            "🔐 sign_transfer_canonical_v3: preimage_hash(first8)={:?} amount={} token={}",
            &preimage_hash.as_bytes()[..8],
            amount,
            token_id
        );

        dsm::crypto::sphincs::sphincs_sign(&signing_key, &signing_bytes).map_err(|e| {
            DsmError::crypto(
                format!("Failed to sign transfer (v3): {e}"),
                None::<std::io::Error>,
            )
        })
    }

    pub async fn execute_token_operation(
        &self,
        operation: TokenOperation,
    ) -> Result<State, DsmError> {
        self.validate_token_operation(&operation)?;
        self.execute_generic_token_operation(&operation).await
    }

    pub async fn validate_token_conservation(&self) -> Result<bool, DsmError> {
        let current_state = self.core_sdk.get_current_state()?;
        let balances = self.balances.read();
        let device_id = current_state.device_info.device_id;

        // Verify cached balances match state for each canonical key.
        // Canonical key format is "{u128}|{token_id}" for all DSM tokens.
        for (key, state_balance) in &current_state.token_balances {
            let token_id = if let Some((_, t)) = key.split_once('|') {
                t
            } else {
                key.as_str()
            };
            if let Some(device_balances) = balances.get(&device_id) {
                if let Some(cached_balance) = device_balances.get(token_id) {
                    if cached_balance.value() != state_balance.value() {
                        log::warn!(
                            "Balance mismatch for {} - cached: {}, state: {}",
                            token_id,
                            cached_balance.value(),
                            state_balance.value()
                        );
                        return Ok(false);
                    }
                }
            }
        }

        let era_token = self.era_token.read();
        let total_era_in_circulation: u64 = balances
            .values()
            .flat_map(|device_balances| device_balances.get("ERA"))
            .map(|balance| balance.value())
            .sum();

        if total_era_in_circulation > era_token.total_supply.value() {
            log::error!(
                "ERA token supply violation: circulation {} exceeds total supply {}",
                total_era_in_circulation,
                era_token.total_supply.value()
            );
            return Ok(false);
        }

        Ok(true)
    }

    pub async fn update_metadata(&self) -> Result<(), DsmError> {
        let current_state = self.core_sdk.get_current_state()?;

        if let Operation::Generic {
            operation_type,
            data,
            ..
        } = &current_state.operation
        {
            if operation_type.as_slice() == b"token_registry_update"
                || operation_type.as_slice() == b"token_create"
            {
                if let Ok(registry_update) = decode_registry_update(data) {
                    for (token_id, metadata) in registry_update {
                        if metadata.token_id != token_id {
                            return Err(DsmError::state(format!(
                                "Registry update key {token_id} did not match metadata token id {}",
                                metadata.token_id
                            )));
                        }
                        self.cache_token_metadata_strict(metadata)?;
                    }
                } else if let Ok(single) = TokenMetadataProto::decode(data.as_slice()) {
                    self.cache_token_metadata_strict(token_metadata_from_proto(&single))?;
                }
            }
        }

        let mut token_ids: Vec<String> = current_state
            .token_balances
            .keys()
            .filter_map(|token_key| {
                let token_id = canonical_token_id_from_balance_key(token_key);
                if token_id.is_none() {
                    log::warn!(
                        "[TokenSDK] Skipping malformed token balance key during metadata refresh: {}",
                        token_key
                    );
                }
                token_id.map(str::to_string)
            })
            .collect();
        token_ids.sort();
        token_ids.dedup();

        for token_id in token_ids {
            self.resolve_token_metadata_strict(&token_id)?
                .ok_or_else(|| {
                    DsmError::state(format!(
                        "Token {token_id} is present in balances but has no canonical metadata"
                    ))
                })?;
        }

        Ok(())
    }

    pub fn create_era_transfer(
        &self,
        from_device_id: &str,
        to_device_id: &str,
        amount: u64,
    ) -> Result<TokenOperation, DsmError> {
        let from_device_id_bytes: [u8; 32] =
            crate::util::domain_helpers::device_id_hash(from_device_id);
        let balances = self.balances.read();
        if let Some(device_id_balances) = balances.get(&from_device_id_bytes) {
            if let Some(balance) = device_id_balances.get("ERA") {
                if balance.value() < amount {
                    return Err(DsmError::invalid_operation(format!(
                        "Insufficient ERA balance for transfer: have {have}, need {need}",
                        have = balance.value(),
                        need = amount
                    )));
                }
            } else {
                return Err(DsmError::invalid_operation(
                    "No ERA balance found for sender",
                ));
            }
        } else {
            return Err(DsmError::invalid_operation("No balances found for sender"));
        }

        Ok(TokenOperation::Transfer {
            token_id: "ERA".to_string(),
            recipient: crate::util::domain_helpers::device_id_hash(to_device_id),
            amount,
            memo: Some("Era token transfer".to_string()),
        })
    }

    async fn execute_generic_token_operation(
        &self,
        operation: &TokenOperation,
    ) -> Result<State, DsmError> {
        let current_state = self.core_sdk.get_current_state()?;
        let state_hash = current_state.hash;

        match operation {
            TokenOperation::Transfer {
                token_id,
                recipient,
                amount,
                ..
            } => {
                let sender = self.core_sdk.get_current_state()?.device_info.device_id;

                let mut op = Operation::Transfer {
                    to_device_id: recipient.to_vec(),
                    amount: Balance::from_state(*amount, state_hash, current_state.state_number),
                    token_id: token_id.as_bytes().to_vec(),
                    mode: TransactionMode::Bilateral,
                    nonce: Vec::new(),
                    verification: VerificationType::Standard,
                    pre_commit: None,
                    message: "Transfer operation via TokenSDK".to_string(),
                    recipient: recipient.to_vec(),
                    to: crate::util::text_id::encode_base32_crockford(recipient).into_bytes(),
                    signature: Vec::new(),
                };

                let signature = self.sign_transfer_operation(&op)?;
                if let Operation::Transfer { signature: sig, .. } = &mut op {
                    *sig = signature;
                }

                // Use full DSM operation path to preserve authorization fields
                let new_state = self.core_sdk.execute_dsm_operation(op)?;
                self.project_balance_cache_from_state(sender, &new_state)?;

                {
                    let mut history = self.transaction_history.write();
                    history.push((operation.clone(), crate::util::deterministic_time::tick()))
                }

                Ok(new_state)
            }
            TokenOperation::Mint {
                token_id,
                recipient: _,
                amount,
                ..
            } => {
                if token_id == "ERA" {
                    let era_token = self.era_token.read();
                    if era_token.circulating_supply.value() + *amount
                        > era_token.total_supply.value()
                    {
                        return Err(DsmError::invalid_operation(
                            "Minting would exceed total ERA supply",
                        ));
                    }
                }

                let policy_commit = self.resolve_policy_commit_strict(token_id)?;
                let signer_pk = current_state.device_info.public_key.clone();
                let authorized_by = current_state.device_info.device_id.to_vec();
                let signing_key = self.signing_key.read().as_ref().cloned().ok_or_else(|| {
                    DsmError::unauthorized(
                        "Signing key not initialized for TokenSDK mint",
                        None::<std::io::Error>,
                    )
                })?;
                let mut mint_msg = b"mint|".to_vec();
                mint_msg.extend_from_slice(&authorized_by);
                let mint_hash =
                    dsm::crypto::blake3::token_domain_hash(&policy_commit, "mint", &mint_msg);
                let mint_sig =
                    dsm::crypto::sphincs::sphincs_sign(&signing_key, mint_hash.as_bytes())
                        .map_err(|e| {
                            DsmError::crypto(
                                format!("Failed to sign mint authorization: {e}"),
                                None::<std::io::Error>,
                            )
                        })?;

                let op = Operation::Mint {
                    amount: Balance::from_state(*amount, state_hash, current_state.state_number),
                    token_id: token_id.as_bytes().to_vec(),
                    authorized_by,
                    proof_of_authorization: encode_embedded_proof(&signer_pk, &mint_sig)?,
                    message: "Mint operation via TokenSDK".to_string(),
                };

                let new_state = self.core_sdk.execute_dsm_operation(op)?;
                self.project_balance_cache_from_state(
                    current_state.device_info.device_id,
                    &new_state,
                )?;

                if token_id == "ERA" {
                    let mut era_token = self.era_token.write();
                    let new_circulation = Balance::from_state(
                        era_token.circulating_supply.value() + *amount,
                        new_state.hash,
                        new_state.state_number,
                    );
                    era_token.circulating_supply = new_circulation;
                }

                {
                    let mut history = self.transaction_history.write();
                    history.push((operation.clone(), crate::util::deterministic_time::tick()));
                }

                Ok(new_state)
            }
            TokenOperation::Burn {
                token_id, amount, ..
            } => {
                let owner_id = self.core_sdk.get_current_state()?.device_info.device_id;
                let policy_commit = self.resolve_policy_commit_strict(token_id)?;
                let signer_pk = current_state.device_info.public_key.clone();

                // 1. Build the op with empty proof (needed for signing preimage)
                let mut op = Operation::Burn {
                    amount: Balance::from_state(*amount, state_hash, current_state.state_number),
                    token_id: token_id.as_bytes().to_vec(),
                    proof_of_ownership: Vec::new(),
                    message: "Burn operation via TokenSDK".to_string(),
                };

                // 2. Sign the serialised op with the device's SPHINCS+ key
                {
                    let signing_key =
                        self.signing_key.read().as_ref().cloned().ok_or_else(|| {
                            DsmError::unauthorized(
                                "Signing key not initialized for TokenSDK burn",
                                None::<std::io::Error>,
                            )
                        })?;
                    let mut burn_msg = b"burn|".to_vec();
                    burn_msg.extend_from_slice(token_id.as_bytes());
                    let burn_hash =
                        dsm::crypto::blake3::token_domain_hash(&policy_commit, "burn", &burn_msg);
                    let sig =
                        dsm::crypto::sphincs::sphincs_sign(&signing_key, burn_hash.as_bytes())
                            .map_err(|e| {
                                DsmError::crypto(
                                    format!("Failed to sign burn authorization: {e}"),
                                    None::<std::io::Error>,
                                )
                            })?;
                    if let Operation::Burn {
                        proof_of_ownership, ..
                    } = &mut op
                    {
                        *proof_of_ownership = encode_embedded_proof(&signer_pk, &sig)?;
                    }
                }

                let new_state = self.core_sdk.execute_dsm_operation(op)?;
                self.project_balance_cache_from_state(owner_id, &new_state)?;

                if token_id == "ERA" {
                    let mut era_token = self.era_token.write();
                    let new_circulation = Balance::from_state(
                        era_token.circulating_supply.value().saturating_sub(*amount),
                        new_state.hash,
                        new_state.state_number,
                    );
                    era_token.circulating_supply = new_circulation;
                }

                {
                    let mut history = self.transaction_history.write();
                    history.push((operation.clone(), crate::util::deterministic_time::tick()));
                }

                Ok(new_state)
            }
            TokenOperation::Create {
                metadata,
                supply,
                fee,
            } => {
                self.validate_token_creation(metadata, supply, *fee)?;

                let creator_id = self.core_sdk.get_current_state()?.device_info.device_id;
                let token_id = self.generate_token_id(&creator_id, metadata)?;

                if self.token_exists(&token_id).await? {
                    return Err(DsmError::invalid_operation(format!(
                        "Token with ID {token_id} already exists"
                    )));
                }

                if *fee > 0 {
                    self.validate_and_charge_fee(&creator_id, *fee, state_hash.to_vec())
                        .await?;
                }

                let token_metadata = TokenMetadata {
                    name: metadata.name.clone(),
                    symbol: metadata.symbol.clone(),
                    description: metadata.description.clone(),
                    icon_url: metadata.icon_url.clone(),
                    decimals: metadata.decimals,
                    fields: metadata.fields.clone(),
                    token_id: token_id.clone(),
                    token_type: metadata.token_type.clone(),
                    owner_id: creator_id,
                    creation_tick: crate::util::deterministic_time::tick(),
                    metadata_uri: metadata.metadata_uri.clone(),
                    policy_anchor: metadata.policy_anchor.clone(),
                };

                // protobuf encoding
                let serialized_metadata = token_metadata_to_proto(&token_metadata).encode_to_vec();

                let op = Operation::Create {
                    message: format!("Token creation: {}", metadata.name),
                    identity_data: creator_id.to_vec(),
                    public_key: Vec::new(),
                    metadata: serialized_metadata,
                    commitment: Vec::new(),
                    proof: Vec::new(),
                    mode: TransactionMode::Bilateral,
                };

                let core_op = Self::convert_to_core_operation(op);
                let new_state = self.core_sdk.execute_transition(core_op)?;

                {
                    let mut metadata_cache = self.token_metadata.write();
                    metadata_cache.insert(token_id.clone(), token_metadata);
                }

                self.project_balance_cache_from_state(creator_id, &new_state)?;

                {
                    let mut history = self.transaction_history.write();
                    history.push((operation.clone(), crate::util::deterministic_time::tick()));
                }

                log::info!("Successfully created token: {token_id}");
                Ok(new_state)
            }
            TokenOperation::Lock {
                token_id,
                amount,
                purpose,
            } => {
                // Only adjust locked portion; total balance unchanged
                // Build deterministic payload bytes for Generic op: token_id | purpose | owner | amount
                let owner_id = self.core_sdk.get_current_state()?.device_info.device_id;
                let mut payload = Vec::new();
                // token_id
                payload.extend_from_slice(&(token_id.len() as u32).to_le_bytes());
                payload.extend_from_slice(token_id.as_bytes());
                // purpose
                payload.extend_from_slice(&(purpose.len() as u32).to_le_bytes());
                payload.extend_from_slice(purpose);
                // owner
                payload.extend_from_slice(&(32u32).to_le_bytes());
                payload.extend_from_slice(&owner_id);
                // amount
                payload.extend_from_slice(&(*amount).to_le_bytes());

                let op = Operation::Generic {
                    operation_type: b"lock".to_vec(),
                    data: payload,
                    message: format!(
                        "Lock {} units of {} for purpose '{}'",
                        amount,
                        token_id,
                        String::from_utf8_lossy(purpose)
                    ),
                    signature: vec![],
                };

                let core_op = Self::convert_to_core_operation(op);
                let new_state = self.core_sdk.execute_transition(core_op)?;

                self.project_balance_cache_from_state(owner_id, &new_state)?;

                {
                    let mut history = self.transaction_history.write();
                    history.push((operation.clone(), crate::util::deterministic_time::tick()));
                }

                Ok(new_state)
            }
            TokenOperation::Unlock {
                token_id,
                amount,
                purpose,
            } => {
                let owner_id = self.core_sdk.get_current_state()?.device_info.device_id;
                let mut payload = Vec::new();
                // token_id
                payload.extend_from_slice(&(token_id.len() as u32).to_le_bytes());
                payload.extend_from_slice(token_id.as_bytes());
                // purpose
                payload.extend_from_slice(&(purpose.len() as u32).to_le_bytes());
                payload.extend_from_slice(purpose);
                // owner
                payload.extend_from_slice(&(32u32).to_le_bytes());
                payload.extend_from_slice(&owner_id);
                // amount
                payload.extend_from_slice(&(*amount).to_le_bytes());

                let op = Operation::Generic {
                    operation_type: b"unlock".to_vec(),
                    data: payload,
                    message: format!(
                        "Unlock {} units of {} for purpose '{}'",
                        amount,
                        token_id,
                        String::from_utf8_lossy(purpose)
                    ),
                    signature: vec![],
                };

                let core_op = Self::convert_to_core_operation(op);
                let new_state = self.core_sdk.execute_transition(core_op)?;

                self.project_balance_cache_from_state(owner_id, &new_state)?;

                {
                    let mut history = self.transaction_history.write();
                    history.push((operation.clone(), crate::util::deterministic_time::tick()));
                }

                Ok(new_state)
            }
            TokenOperation::Receive {
                token_id,
                sender,
                amount,
                memo,
                sender_state_hash,
            } => {
                let device_id = self.core_sdk.get_current_state()?.device_info.device_id;

                let message = match memo {
                    Some(m) => m.clone(),
                    None => format!(
                        "Received {amount} {token_id} from {}",
                        crate::util::text_id::encode_base32_crockford(sender)
                    ),
                };

                let op = Operation::Receive {
                    token_id: token_id.as_bytes().to_vec(),
                    from_device_id: sender.to_vec(),
                    amount: Balance::from_state(*amount, state_hash, current_state.state_number),
                    recipient: device_id.to_vec(),
                    message,
                    mode: TransactionMode::Bilateral,
                    nonce: self.generate_nonce(),
                    verification: VerificationType::Standard,
                    sender_state_hash: sender_state_hash.clone(),
                };

                let core_op = Self::convert_to_core_operation(op);
                let new_state = self.core_sdk.execute_transition(core_op)?;

                self.project_balance_cache_from_state(device_id, &new_state)?;

                {
                    let mut history = self.transaction_history.write();
                    history.push((
                        TokenOperation::Receive {
                            token_id: token_id.clone(),
                            sender: *sender,
                            amount: *amount,
                            memo: memo.clone(),
                            sender_state_hash: sender_state_hash.clone(),
                        },
                        crate::util::deterministic_time::tick(),
                    ));
                }

                Ok(new_state)
            }
        }
    }

    pub fn calculate_fee(&self, operation_type: &str) -> Balance {
        let era_token = self.era_token.read();
        era_token.get_fee(operation_type)
    }

    pub async fn process_fee_payment(
        &self,
        _from_device_id: &str,
        operation_type: &str,
    ) -> Result<State, DsmError> {
        let fee = self.calculate_fee(operation_type);

        let fee_recipient_str = "system.fee.device_id";
        let mut fee_recipient = [0u8; 32];
        fee_recipient.copy_from_slice(&crate::util::domain_helpers::device_id_hash(
            fee_recipient_str,
        ));

        let fee_op = TokenOperation::Transfer {
            token_id: "ERA".to_string(),
            recipient: fee_recipient,
            amount: fee.value(),
            memo: Some("Fee payment".to_string()),
        };

        self.execute_generic_token_operation(&fee_op).await
    }

    #[allow(dead_code)]
    fn get_era_token_info(&self) -> EraToken {
        self.era_token.read().clone()
    }

    /// Lane router: dispatches to the correct lane-specific reader based on token type.
    pub fn get_token_balance(&self, device_id: &[u8; 32], token_id: &str) -> Balance {
        match classify_token(token_id) {
            TokenLane::Dbtc => self.get_dbtc_balance(device_id),
            TokenLane::Canonical => self.get_canonical_token_balance(device_id, token_id),
        }
    }

    fn get_canonical_token_balance(&self, device_id: &[u8; 32], token_id: &str) -> Balance {
        let balances = self.balances.read();
        if let Some(b) = balances
            .get(device_id)
            .and_then(|m| m.get(token_id))
            .cloned()
        {
            return b;
        }
        if let Some(balance) = self.read_projected_balance(device_id, token_id) {
            drop(balances);
            self.balances
                .write()
                .entry(*device_id)
                .or_default()
                .insert(token_id.to_string(), balance.clone());
            return balance;
        }
        Balance::zero()
    }

    /// dBTC lane: canonical key via make_balance_key(pk, "dBTC").
    /// dBTC reads prefer canonical state and only fall back to validated projections.
    fn get_dbtc_balance(&self, device_id: &[u8; 32]) -> Balance {
        self.get_canonical_token_balance(device_id, "dBTC")
    }

    pub fn has_sufficient_era(&self, device_id: &str, required_amount: u64) -> bool {
        let device_id_bytes: [u8; 32] = crate::util::domain_helpers::device_id_hash(device_id);
        self.get_canonical_token_balance(&device_id_bytes, "ERA")
            .value()
            >= required_amount
    }

    fn generate_nonce(&self) -> Vec<u8> {
        dsm::crypto::generate_nonce_32()
    }

    pub fn create_transfer_operation(
        &self,
        recipient: String,
        amount: Balance,
        token_id: String,
        message: String,
        use_bilateral: bool,
    ) -> Result<Operation, DsmError> {
        let mut op = Operation::Transfer {
            to_device_id: recipient.as_bytes().to_vec(),
            amount,
            token_id: token_id.into_bytes(),
            message,
            mode: if use_bilateral {
                TransactionMode::Bilateral
            } else {
                TransactionMode::Unilateral
            },
            nonce: Vec::new(),
            verification: VerificationType::Standard,
            pre_commit: None,
            recipient: recipient.as_bytes().to_vec(),
            to: recipient.clone().into_bytes(),
            signature: Vec::new(),
        };

        let signature = self.sign_transfer_operation(&op)?;
        if let Operation::Transfer { signature: sig, .. } = &mut op {
            *sig = signature;
        }

        Ok(op)
    }

    pub fn create_token_operation(&self, params: CreateTokenParams) -> Result<Operation, DsmError> {
        let mut metadata = Vec::new();
        for value in params.metadata.values() {
            metadata.extend_from_slice(value);
        }

        Ok(Operation::Create {
            message: "Token creation operation".to_string(),
            identity_data: params.identity_data,
            public_key: vec![],
            metadata, // caller may pass protobuf-encoded metadata bytes here
            commitment: params.commitment,
            proof: params.proof,
            mode: TransactionMode::Bilateral,
        })
    }

    pub fn transfer_token_operation(
        &self,
        _from: String,
        to: String,
        _proof: Vec<u8>,
    ) -> Result<Operation, DsmError> {
        let mut op = Operation::Transfer {
            to_device_id: to.as_bytes().to_vec(),
            amount: Balance::zero(),
            token_id: vec![],
            mode: TransactionMode::Bilateral,
            nonce: self.generate_nonce(),
            verification: VerificationType::Standard,
            pre_commit: None,
            message: "Transfer operation via TokenSDK".to_string(),
            recipient: to.as_bytes().to_vec(),
            to: to.into_bytes(),
            signature: Vec::new(),
        };

        let signature = self.sign_transfer_operation(&op)?;
        if let Operation::Transfer { signature: sig, .. } = &mut op {
            *sig = signature;
        }

        Ok(op)
    }

    /// Execute a smart commitment
    #[allow(dead_code)]
    async fn execute_commitment(
        &self,
        commitment: &DsmSmartCommitment,
    ) -> Result<Operation, DsmError> {
        let id = commitment.id.clone();

        let mut op = Operation::Transfer {
            to_device_id: id.as_bytes().to_vec(),
            amount: Balance::zero(),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: self.generate_nonce(),
            verification: VerificationType::Standard,
            pre_commit: None,
            message: "Smart commitment transfer".to_string(),
            recipient: id.as_bytes().to_vec(),
            to: id.into_bytes(),
            signature: Vec::new(),
        };

        let signature = self.sign_transfer_operation(&op)?;
        if let Operation::Transfer { signature: sig, .. } = &mut op {
            *sig = signature;
        }

        Ok(op)
    }

    pub async fn adjust_fees(
        &self,
        network_load: f64,
        state_hash: Vec<u8>,
    ) -> Result<(), DsmError> {
        let mut era_token = self.era_token.write();

        let mut new_schedule = HashMap::new();
        for (op_type, base_fee) in era_token.fee_schedule.iter() {
            let adjusted_fee = (base_fee.value() as f64 * (1.0 + network_load * 0.1)) as u64;
            new_schedule.insert(
                op_type.clone(),
                Balance::from_state(
                    adjusted_fee,
                    state_hash.clone().try_into().unwrap_or([0u8; 32]),
                    0,
                ),
            );
        }

        era_token.fee_schedule = new_schedule;
        Ok(())
    }

    pub fn verify_operation_feasibility(
        &self,
        from_device_id: &str,
        operation: &TokenOperation,
        operation_type: &str,
    ) -> Result<(), DsmError> {
        let fee = self.calculate_fee(operation_type);
        let total_required: u64 = match operation {
            TokenOperation::Transfer { amount, .. } => *amount + fee.value(),
            TokenOperation::Burn { amount, .. } => *amount + fee.value(),
            _ => fee.value(),
        };

        if !self.has_sufficient_era(from_device_id, total_required) {
            return Err(DsmError::invalid_operation(format!(
                "Insufficient ERA balance for operation and fee. Required: {total_required}"
            )));
        }

        Ok(())
    }

    /// Seed the in-memory balance for a device/token from a validated external
    /// source without advancing the state machine.
    ///
    /// Only seeds upward: if the map already has a value >= `amount` it is left
    /// unchanged — a tracked in-memory spend must not be wiped by a stale read.
    /// If the token is absent or the tracked in-memory value is below `amount`,
    /// it is set to `amount`.
    ///
    /// This is the correct fix for bilateral-receive tokens: bilateral receive
    /// may hydrate derived storage before the in-memory map is refreshed. Without seeding, the first Burn
    /// of a bilaterally-received token would hit an "Insufficient balance" error
    /// *after* `execute_dsm_operation` has already advanced the state machine,
    /// leaving canonical state and the cache out of sync.
    pub fn seed_in_memory_balance(
        &self,
        device_id: DevId,
        token_id: &str,
        amount: u64,
    ) -> Result<(), DsmError> {
        if amount == 0 {
            return Ok(());
        }
        let current_state = self.core_sdk.get_current_state()?;
        let state_hash = current_state.hash;
        let state_number = current_state.state_number;
        let mut balances = self.balances.write();
        let device_balances = balances.entry(device_id).or_default();
        let current = device_balances
            .get(token_id)
            .map(|b| b.value())
            .unwrap_or(0);
        if current < amount {
            device_balances.insert(
                token_id.to_string(),
                Balance::from_state(amount, state_hash, state_number),
            );
        }
        Ok(())
    }

    /// Unconditionally set the in-memory balance for a device+token pair.
    /// Used by the atomic b0x rollback path to restore the pre-send balance
    /// after a failed storage-node delivery.
    pub fn force_set_balance(&self, device_id: DevId, token_id: &str, amount: u64) {
        let (state_hash, state_number) = self
            .core_sdk
            .get_current_state()
            .map(|s| (s.hash, s.state_number))
            .unwrap_or(([0u8; 32], 0));
        let mut balances = self.balances.write();
        let device_balances = balances.entry(device_id).or_default();
        device_balances.insert(
            token_id.to_string(),
            Balance::from_state(amount, state_hash, state_number),
        );
    }

    pub fn discard_transfer_history_entry(
        &self,
        token_id: &str,
        recipient_device_id: &[u8; 32],
        amount: u64,
        memo: Option<&str>,
    ) -> bool {
        let mut history = self.transaction_history.write();
        if let Some(idx) = history.iter().rposition(|(op, _)| {
            matches!(
                op,
                TokenOperation::Transfer {
                    token_id: tid,
                    recipient,
                    amount: amt,
                    memo: op_memo,
                } if tid == token_id
                    && recipient == recipient_device_id
                    && *amt == amount
                    && op_memo.as_deref() == memo
            )
        }) {
            history.remove(idx);
            return true;
        }
        false
    }

    /// Reload the local in-memory balance cache from the authoritative
    /// canonical state when present, falling back to validated projections
    /// only on cold start.
    pub fn reload_balance_cache_for_self(&self, device_id: DevId) -> Result<(), DsmError> {
        let device_id_str = crate::util::text_id::encode_base32_crockford(&device_id);
        if let Ok(current_state) = self.core_sdk.get_current_state() {
            return self.project_balance_cache_from_state(device_id, &current_state);
        }

        let mut reloaded = HashMap::new();
        if let Ok(token_balances) =
            crate::storage::client_db::list_balance_projections(&device_id_str)
        {
            for record in token_balances {
                let source_hash =
                    crate::util::text_id::decode_base32_crockford(&record.source_state_hash)
                        .and_then(|bytes| bytes.try_into().ok())
                        .unwrap_or([0u8; 32]);
                let mut balance =
                    Balance::from_state(record.available, source_hash, record.source_state_number);
                if record.locked > 0 {
                    let _ = balance.lock(record.locked);
                }
                reloaded.insert(record.token_id, balance);
            }
        }

        let mut balances = self.balances.write();
        balances.insert(device_id, reloaded);

        Ok(())
    }

    pub fn validate_token_operation(&self, operation: &TokenOperation) -> Result<(), DsmError> {
        match operation {
            TokenOperation::Transfer { amount, .. }
            | TokenOperation::Burn { amount, .. }
            | TokenOperation::Mint { amount, .. } => {
                if *amount == 0 {
                    return Err(DsmError::invalid_operation("Amount must be positive"));
                }
            }
            TokenOperation::Create { .. } => {
                return Err(DsmError::invalid_operation(
                    "Token creation requires proper authorization",
                ));
            }
            TokenOperation::Lock {
                token_id,
                amount,
                purpose: _,
            } => {
                if *amount == 0 {
                    return Err(DsmError::invalid_operation("Amount must be positive"));
                }
                // Ensure free balance >= amount
                let owner = self.core_sdk.get_current_state()?.device_info.device_id;
                let bal = self.get_token_balance(&owner, token_id);
                if bal.value() < *amount {
                    return Err(DsmError::invalid_operation("Insufficient balance to lock"));
                }
            }
            TokenOperation::Unlock {
                token_id,
                amount,
                purpose,
            } => {
                if *amount == 0 {
                    return Err(DsmError::invalid_operation("Amount must be positive"));
                }
                let owner = self.core_sdk.get_current_state()?.device_info.device_id;
                let state_hash = self.core_sdk.get_current_state()?.hash;
                let purpose_str = String::from_utf8_lossy(purpose);
                let locked = futures::executor::block_on(self.get_locked_balance(
                    &owner,
                    token_id,
                    &purpose_str,
                    state_hash.to_vec(),
                ))?;
                if locked.value() < *amount {
                    return Err(DsmError::invalid_operation(
                        "Unlock amount exceeds locked balance",
                    ));
                }
            }
            TokenOperation::Receive { amount, .. } => {
                if *amount == 0 {
                    return Err(DsmError::invalid_operation("Amount must be positive"));
                }
            }
        }
        Ok(())
    }

    pub async fn recover_from_failed_operation(
        &self,
        operation: &TokenOperation,
        error: &DsmError,
    ) -> Result<(), DsmError> {
        log::error!("Operation failed: {operation:?} with error: {error}");

        match error {
            DsmError::State(_) => {
                self.update_metadata().await?;
                Ok(())
            }
            DsmError::Validation { .. }
            | DsmError::InvalidParameter(_)
            | DsmError::InvalidOperation(_) => {
                if !self.validate_token_conservation().await? {
                    return Err(DsmError::Validation {
                        context: "Token conservation violation detected".to_string(),
                        source: None,
                    });
                }
                Ok(())
            }
            DsmError::Network { .. } => Ok(()),
            _ => {
                log::warn!("Unhandled error type: {error:?}");
                Ok(())
            }
        }
    }

    /// Deterministic canonical preimage for a transfer op (no bincode/JSON).
    fn canonical_transfer_preimage(
        prev_state_hash: &[u8],
        token_id: &str,
        recipient: &[u8; 32],
        amount: u64,
        memo: Option<&str>,
        nonce: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            prev_state_hash.len() + 1 + 2 + token_id.len() + 32 + 8 + 2 + nonce.len(),
        );

        // Prefix previous state hash
        buf.extend_from_slice(prev_state_hash);

        // Discriminator for op type
        buf.push(0x01); // TRANSFER

        // token_id
        buf.extend_from_slice(&(token_id.len() as u16).to_le_bytes());
        buf.extend_from_slice(token_id.as_bytes());

        // recipient (fixed 32 bytes)
        buf.extend_from_slice(&(32u16).to_le_bytes());
        buf.extend_from_slice(recipient);

        // amount
        buf.extend_from_slice(&amount.to_le_bytes());

        // memo (optional)
        if let Some(m) = memo {
            buf.push(0x01);
            buf.extend_from_slice(&(m.len() as u16).to_le_bytes());
            buf.extend_from_slice(m.as_bytes());
        } else {
            buf.push(0x00);
        }

        // nonce
        buf.extend_from_slice(&(nonce.len() as u16).to_le_bytes());
        buf.extend_from_slice(nonce);

        buf
    }

    pub async fn execute_bilateral_token_transfer(
        &self,
        token_id: String,
        recipient: [u8; 32],
        amount: u64,
        recipient_public_key: Vec<u8>,
        memo: Option<String>,
        state_hash: Vec<u8>,
    ) -> Result<State, DsmError> {
        use dsm::types::operations::PreCommitmentOp;
        use std::collections::{HashMap, HashSet};

        let current_state = self.core_sdk.get_current_state()?;
        let sender = current_state.device_info.device_id;

        let next_entropy = dsm::crypto::generate_nonce_32();

        // Deterministic preimage (no bincode/JSON)
        let preimage = Self::canonical_transfer_preimage(
            &current_state.hash,
            &token_id,
            &recipient,
            amount,
            memo.as_deref(),
            &next_entropy,
        );
        let _next_state_hash = dsm::crypto::blake3::domain_hash("DSM/state-hash", &preimage)
            .as_bytes()
            .to_vec();

        let mut fixed_parameters = HashMap::new();
        fixed_parameters.insert("token_id".to_string(), token_id.clone().into_bytes());
        fixed_parameters.insert("recipient".to_string(), recipient.to_vec());
        fixed_parameters.insert("amount".to_string(), amount.to_string().into_bytes());
        fixed_parameters.insert("sender".to_string(), sender.to_vec());
        fixed_parameters.insert("operation_type".to_string(), b"transfer".to_vec());

        let variable_parameters = HashSet::new();

        // forward commitment object used by higher layers (pre-commit op is what the protocol consumes)
        let pre_commitment_op = PreCommitmentOp {
            fixed_parameters: fixed_parameters.clone(),
            variable_parameters: variable_parameters.iter().cloned().collect(),
            ..Default::default()
        };

        if recipient_public_key.is_empty() {
            return Err(DsmError::invalid_parameter(
                "recipient_public_key must be present for bilateral transfers",
            ));
        }

        let mut bilateral_transfer_op = Operation::Transfer {
            token_id: token_id.as_bytes().to_vec(),
            to_device_id: recipient.to_vec(),
            amount: Balance::from_state(
                amount,
                state_hash.clone().try_into().unwrap_or([0u8; 32]),
                current_state.state_number,
            ),
            recipient: recipient_public_key,
            message: memo.clone().unwrap_or_else(|| {
                format!(
                    "Bilateral transfer of {amount} tokens to {}",
                    crate::util::text_id::encode_base32_crockford(&recipient)
                )
            }),
            mode: TransactionMode::Bilateral,
            nonce: next_entropy.clone(),
            verification: VerificationType::Standard,
            pre_commit: Some(pre_commitment_op),
            to: crate::util::text_id::encode_base32_crockford(&recipient).into_bytes(),
            signature: Vec::new(),
        };

        let signature = self.sign_transfer_operation(&bilateral_transfer_op)?;
        if let Operation::Transfer { signature: sig, .. } = &mut bilateral_transfer_op {
            *sig = signature;
        }

        // Preserve full authorization fields (signature/proofs) if present
        let new_state = self.core_sdk.execute_dsm_operation(bilateral_transfer_op)?;
        self.project_balance_cache_from_state(sender, &new_state)?;

        let recipient_id = crate::util::domain_helpers::device_id_hash_bytes(&recipient);

        {
            let token_op = TokenOperation::Transfer {
                token_id: token_id.clone(),
                recipient: recipient_id,
                amount,
                memo: Some("Bilateral transfer with cryptographic commitment".to_string()),
            };

            let mut history = self.transaction_history.write();
            history.push((token_op, crate::util::deterministic_time::tick()));
        }

        Ok(new_state)
    }

    pub async fn execute_simplified_bilateral_transfer(
        &self,
        token_id: String,
        recipient: String,
        amount: u64,
        memo: Option<String>,
    ) -> Result<(State, String), DsmError> {
        let current_state = self.core_sdk.get_current_state()?;
        let _sender_id = current_state.device_info.device_id;

        let recipient_id = crate::util::domain_helpers::device_id_hash(recipient.as_str());

        log::info!("Verifying recipient Genesis state");
        if !self.genesis_state_cache.has_verified_genesis(&recipient) {
            let _ = self
                .genesis_state_cache
                .fetch_and_cache_genesis(&recipient)
                .await?;
            log::info!("Recipient Genesis state verified successfully");
        }

        let recipient_genesis = match self.genesis_state_cache.get_cached_genesis(&recipient) {
            Some(genesis) => genesis,
            None => {
                return Err(DsmError::NotFound {
                    entity: "Recipient Genesis state".to_string(),
                    details: Some("Recipient Genesis state not found".to_string()),
                    context: "Genesis state lookup failed".to_string(),
                    source: None,
                })
            }
        };

        let transfer_id = format!(
            "bilateral_{}_{}_{}",
            crate::util::text_id::encode_base32_crockford(&self.generate_nonce()[0..8]),
            current_state.state_number,
            crate::util::deterministic_time::tick()
        );

        let _recipient_genesis_id = crate::util::text_id::short_id(&recipient_genesis.hash, 8);

        let message = memo
            .clone()
            .unwrap_or_else(|| format!("Bilateral transfer of {amount} {token_id} to {recipient}"));

        let sender_op = TokenOperation::Transfer {
            token_id: token_id.clone(),
            recipient: recipient_id,
            amount,
            memo: Some(format!("SEND: {message}")),
        };

        let sender_state = self.execute_token_operation(sender_op).await?;

        log::info!(
            "Sender state transition complete: #{}",
            sender_state.state_number
        );
        log::info!("Bilateral transfer initialized with ID: {transfer_id}");

        Ok((sender_state, transfer_id))
    }

    pub async fn complete_bilateral_transfer(
        &self,
        token_id: String,
        sender_id: String,
        amount: u64,
        transfer_id: String,
        sender_state_hash: Vec<u8>,
    ) -> Result<State, DsmError> {
        log::info!("Completing bilateral transfer as recipient");

        let sender_device_id = crate::util::domain_helpers::device_id_hash(sender_id.as_str());

        if !self.genesis_state_cache.has_verified_genesis(&sender_id) {
            let _ = self
                .genesis_state_cache
                .fetch_and_cache_genesis(&sender_id)
                .await?;
            log::info!("Sender Genesis state verified successfully");
        }

        let sender_genesis = match self.genesis_state_cache.get_cached_genesis(&sender_id) {
            Some(genesis) => genesis,
            None => {
                return Err(DsmError::NotFound {
                    entity: "Sender Genesis state".to_string(),
                    details: Some("Sender Genesis state not found".to_string()),
                    context: "Genesis state lookup failed".to_string(),
                    source: None,
                })
            }
        };

        let current_state = self.core_sdk.get_current_state()?;
        let _recipient_id = current_state.device_info.device_id;

        let sender_genesis_id = crate::util::text_id::short_id(&sender_genesis.hash, 8);

        let recipient_op = TokenOperation::Receive {
            token_id: token_id.clone(),
            sender: sender_device_id,
            amount,
            memo: Some(format!(
                "RECEIVE: Bilateral transfer (ID: {transfer_id}, SenderGenesis: {sender_genesis_id})"
            )),
            sender_state_hash: Some(sender_state_hash),
        };

        let recipient_state = self.execute_token_operation(recipient_op).await?;

        log::info!(
            "Recipient state transition complete: #{}",
            recipient_state.state_number
        );

        Ok(recipient_state)
    }

    pub async fn verify_and_merge_bilateral_states(
        &self,
        transfer_id: &str,
        sender_state_hash: &[u8],
        recipient_state_hash: &[u8],
    ) -> Result<bool, DsmError> {
        log::info!("Verifying and merging bilateral transfer states");

        let branch_id = format!("bilateral_{transfer_id}");

        let mut combined_hash = Vec::new();
        combined_hash.extend_from_slice(sender_state_hash);
        combined_hash.extend_from_slice(recipient_state_hash);

        let current_state = self.core_sdk.get_current_state()?;
        let _device_id = current_state.device_info.device_id;

        log::info!("Transfer ID: {transfer_id}");
        log::info!("Branch ID: {branch_id}");
        log::info!(
            "Sender state hash: {}",
            crate::util::text_id::encode_base32_crockford(sender_state_hash)
        );
        log::info!(
            "Recipient state hash: {}",
            crate::util::text_id::encode_base32_crockford(recipient_state_hash)
        );
        log::info!(
            "Combined hash (chain tip ID): {}",
            crate::util::text_id::encode_base32_crockford(&combined_hash)
        );

        Ok(true)
    }

    pub fn get_bilateral_chain_tip_id(&self, transfer_id: &str) -> Result<String, DsmError> {
        let branch_id = format!("bilateral_{transfer_id}");
        let tip_id = format!("tip_{branch_id}");
        log::info!("Retrieved chain tip ID for transfer {transfer_id}: {tip_id}");
        Ok(tip_id)
    }

    pub async fn get_balance(
        &self,
        token_id: &str,
        _state_hash: Vec<u8>,
    ) -> Result<Balance, DsmError> {
        let device_id = self
            .core_sdk
            .get_current_state()
            .map_err(|_| DsmError::internal("No current state available", None::<std::io::Error>))?
            .device_info
            .device_id;
        Ok(self.get_token_balance(&device_id, token_id))
    }

    /// Protobuf transfer history (encoded TransferRecord bytes).
    pub async fn get_transfer_history(
        &self,
        token_id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<Vec<u8>>, DsmError> {
        let records = self.get_transfer_history_pb(token_id, limit).await?;
        Ok(records.into_iter().map(|r| r.encode_to_vec()).collect())
    }

    /// Protobuf transfer history.
    pub async fn get_transfer_history_pb(
        &self,
        token_id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<TransferRecord>, DsmError> {
        let mut out = Vec::new();
        let hist = self.transaction_history.read();

        for (op, tick) in hist.iter().rev() {
            match op {
                TokenOperation::Transfer {
                    token_id: tid,
                    recipient,
                    amount,
                    memo,
                } if tid == token_id => {
                    let from = self.core_sdk.get_current_state()?.device_info.device_id;
                    let rec = TransferRecord {
                        token_id: tid.clone(),
                        from_device_id: crate::util::text_id::encode_base32_crockford(&from),
                        to_device_id: crate::util::text_id::encode_base32_crockford(recipient),
                        amount: *amount,
                        memo: memo.clone(),
                        state_number: self.core_sdk.get_current_state()?.state_number,
                        tick: *tick,
                    };
                    out.push(rec);
                }
                TokenOperation::Receive {
                    token_id: tid,
                    sender,
                    amount,
                    memo,
                    ..
                } if tid == token_id => {
                    let to = self.core_sdk.get_current_state()?.device_info.device_id;
                    let rec = TransferRecord {
                        token_id: tid.clone(),
                        from_device_id: crate::util::text_id::encode_base32_crockford(sender),
                        to_device_id: crate::util::text_id::encode_base32_crockford(&to),
                        amount: *amount,
                        memo: memo.clone(),
                        state_number: self.core_sdk.get_current_state()?.state_number,
                        tick: *tick,
                    };
                    out.push(rec);
                }
                _ => {}
            }

            if let Some(lim) = limit {
                if out.len() >= lim {
                    break;
                }
            }
        }
        Ok(out)
    }

    pub async fn list_owned_tokens(&self) -> Result<Vec<TokenMetadata>, DsmError> {
        let current_state = self.core_sdk.get_current_state()?;
        let mut token_ids: Vec<String> = current_state
            .token_balances
            .iter()
            .filter_map(|(token_key, balance)| {
                if balance.value() == 0 {
                    return None;
                }
                let token_id = canonical_token_id_from_balance_key(token_key);
                if token_id.is_none() {
                    log::warn!(
                        "[TokenSDK] Skipping malformed token balance key while listing owned tokens: {}",
                        token_key
                    );
                }
                token_id.map(str::to_string)
            })
            .collect();
        token_ids.sort();
        token_ids.dedup();

        let mut tokens = Vec::with_capacity(token_ids.len());
        for token_id in token_ids {
            if let Some(metadata) = self.resolve_token_metadata_strict(&token_id)? {
                tokens.push(metadata);
            } else {
                return Err(DsmError::state(format!(
                    "Token {token_id} has balance but no canonical metadata"
                )));
            }
        }

        Ok(tokens)
    }

    fn validate_token_creation(
        &self,
        metadata: &TokenMetadata,
        supply: &TokenSupply,
        fee: u64,
    ) -> Result<(), DsmError> {
        if metadata.name.is_empty() {
            return Err(DsmError::invalid_operation("Token name cannot be empty"));
        }

        if metadata.symbol.is_empty() {
            return Err(DsmError::invalid_operation("Token symbol cannot be empty"));
        }

        if metadata.decimals > 18 {
            return Err(DsmError::invalid_operation(
                "Token decimals cannot exceed 18",
            ));
        }

        match supply {
            TokenSupply::Fixed(amount) => {
                if *amount == 0 {
                    return Err(DsmError::invalid_operation("Fixed supply cannot be zero"));
                }
            }
            TokenSupply::Unlimited => {}
        }

        let creator_id = self.core_sdk.get_current_state()?.device_info.device_id;
        let era_balance = self.get_token_balance(&creator_id, "ERA");

        if era_balance.value() < fee {
            return Err(DsmError::invalid_operation(format!(
                "Insufficient ERA balance for fee. Required: {}, Available: {}",
                fee,
                era_balance.value()
            )));
        }

        Ok(())
    }

    fn generate_token_id(
        &self,
        creator_id: &[u8; 32],
        metadata: &TokenMetadata,
    ) -> Result<String, DsmError> {
        let proto = token_metadata_to_proto(metadata);
        let metadata_bytes = proto.encode_to_vec();
        let hash = dsm::crypto::blake3::domain_hash("DSM/token-metadata", &metadata_bytes);
        let short_hash = crate::util::text_id::encode_base32_crockford(&hash.as_bytes()[0..8]);
        let creator_id_str = crate::util::text_id::encode_base32_crockford(creator_id);

        Ok(format!("{creator_id_str}_{short_hash}"))
    }

    async fn token_exists(&self, token_id: &str) -> Result<bool, DsmError> {
        {
            let metadata = self.token_metadata.read();
            if metadata.contains_key(token_id) {
                return Ok(true);
            }
        }

        match self.find_token_metadata_state(token_id) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    async fn validate_and_charge_fee(
        &self,
        _creator_id: &[u8; 32],
        fee: u64,
        state_hash: Vec<u8>,
    ) -> Result<(), DsmError> {
        if fee == 0 {
            return Ok(());
        }

        let current_state = self.core_sdk.get_current_state()?;
        let mut fee_transfer_op = Operation::Transfer {
            to_device_id: b"system.fee.device_id".to_vec(),
            amount: Balance::from_state(
                fee,
                state_hash.clone().try_into().unwrap_or([0u8; 32]),
                current_state.state_number,
            ),
            token_id: b"ERA".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: self.generate_nonce(),
            verification: VerificationType::Standard,
            pre_commit: None,
            message: "Fee payment".to_string(),
            recipient: b"system.fee.device_id".to_vec(),
            to: b"system.fee.device_id".to_vec(),
            signature: Vec::new(),
        };

        let signature = self.sign_transfer_operation(&fee_transfer_op)?;
        if let Operation::Transfer { signature: sig, .. } = &mut fee_transfer_op {
            *sig = signature;
        }

        let new_state = self.core_sdk.execute_dsm_operation(fee_transfer_op)?;
        self.project_balance_cache_from_state(current_state.device_info.device_id, &new_state)?;
        Ok(())
    }

    async fn get_balance_for_device(
        &self,
        device_id: &str,
        token_id: &str,
    ) -> Result<Balance, DsmError> {
        let device_id_bytes: [u8; 32] = crate::util::domain_helpers::device_id_hash(device_id);
        Ok(self.get_token_balance(&device_id_bytes, token_id))
    }

    async fn get_locked_balance(
        &self,
        device_id: &[u8; 32],
        token_id: &str,
        purpose: &str,
        state_hash: Vec<u8>,
    ) -> Result<Balance, DsmError> {
        // Previously this parsed a JSON map in state parameters.
        // Now it expects protobuf LockedBalances in the "locked_balances" parameter.
        let device_id_str = crate::util::text_id::encode_base32_crockford(device_id);
        let locked_key = format!("{device_id_str}:{token_id}:{purpose}");

        if let Ok(current_state) = self.core_sdk.get_current_state() {
            if let Some(locked_blob) = current_state.get_parameter("locked_balances") {
                if let Ok(proto) = LockedBalances::decode(locked_blob.as_slice()) {
                    if let Some(entry) = proto.entries.iter().find(|e| e.key == locked_key) {
                        return Ok(Balance::from_state(
                            entry.amount,
                            state_hash.clone().try_into().unwrap_or([0u8; 32]),
                            current_state.state_number,
                        ));
                    }
                } else {
                    // If decoding fails, treat as no locked balance (fail-closed).
                    log::warn!("LockedBalances parameter present but not decodable as protobuf; treating as zero.");
                }
            }
        }

        // Fallback to in-memory locks if tracked on Balance
        let balances = self.balances.read();
        if let Some(device_balances) = balances.get(device_id) {
            if let Some(balance) = device_balances.get(token_id) {
                return Ok(Balance::from_state(
                    balance.locked(),
                    state_hash.clone().try_into().unwrap_or([0u8; 32]),
                    0,
                ));
            }
        }

        Ok(Balance::zero())
    }

    pub async fn import_token_metadata(
        &self,
        token_id: String,
        metadata: TokenMetadata,
    ) -> Result<(), DsmError> {
        {
            let mut token_md = self.token_metadata.write();
            token_md.insert(token_id.clone(), metadata.clone());
        }

        let mut registry_update = HashMap::new();
        registry_update.insert(token_id.clone(), metadata);

        let serialized_data = encode_registry_update(&registry_update)?;

        let op = Operation::Generic {
            operation_type: b"token_registry_update".to_vec(),
            data: serialized_data,
            message: format!("Import token metadata for {token_id}"),
            signature: vec![],
        };

        let core_op = Self::convert_to_core_operation(op);
        self.core_sdk.execute_transition(core_op)?;

        Ok(())
    }

    pub async fn get_token_metadata(
        &self,
        token_id: &str,
    ) -> Result<Option<TokenMetadata>, DsmError> {
        self.resolve_token_metadata_strict(token_id)
    }

    pub fn get_available_tokens(&self) -> Vec<String> {
        let mut tokens = Vec::new();

        if let Ok(current_state) = self.core_sdk.get_current_state() {
            for token_key in current_state.token_balances.keys() {
                if let Some(token_id) = canonical_token_id_from_balance_key(token_key) {
                    tokens.push(token_id.to_string());
                } else {
                    log::warn!(
                        "[TokenSDK] Skipping malformed token balance key while listing available tokens: {}",
                        token_key
                    );
                }
            }
        }

        {
            let metadata = self.token_metadata.read();
            for token_id in metadata.keys() {
                if !tokens.contains(token_id) {
                    tokens.push(token_id.clone());
                }
            }
        }

        tokens.sort();
        tokens.dedup();
        tokens
    }

    /// Execute a signed transfer carrying the sender's SPHINCS+ signature.
    /// This ensures the state machine receives the authorization material.
    pub async fn execute_signed_transfer(
        &self,
        token_id: String,
        recipient: String,
        amount: u64,
        memo: Option<String>,
        signature: Vec<u8>,
    ) -> Result<State, DsmError> {
        let current_state = self.core_sdk.get_current_state()?;
        let state_hash = current_state.hash;
        let sender = current_state.device_info.device_id;

        // Canonical recipient form is raw 32-byte device_id. The caller passes
        // base32 text; decode here and fail closed on malformed input.
        let recipient_device_id = crate::util::text_id::decode_base32_crockford(&recipient)
            .ok_or_else(|| DsmError::invalid_parameter("recipient must be base32"))?;
        if recipient_device_id.len() != 32 {
            return Err(DsmError::invalid_parameter(
                "recipient must decode to 32 bytes",
            ));
        }

        let mut op = Operation::Transfer {
            to_device_id: recipient_device_id.clone(),
            amount: Balance::from_state(amount, state_hash, current_state.state_number),
            token_id: token_id.as_bytes().to_vec(),
            mode: TransactionMode::Unilateral,
            nonce: Vec::new(),
            verification: VerificationType::Standard,
            pre_commit: None,
            recipient: recipient_device_id.clone(),
            to: recipient.as_bytes().to_vec(),
            message: memo
                .clone()
                .unwrap_or_else(|| "Transfer via WalletSDK".to_string()),
            signature: Vec::new(),
        };

        let applied_signature = match self.sign_transfer_operation(&op) {
            Ok(sig) => sig,
            Err(e) => {
                if signature.is_empty() {
                    return Err(e);
                }
                log::warn!(
                    "Falling back to provided transfer signature because local signing key was unavailable: {e}"
                );
                signature
            }
        };

        if let Operation::Transfer { signature: sig, .. } = &mut op {
            *sig = applied_signature;
        }

        log::debug!("[TOKEN] execute_signed_transfer: calling core_sdk.execute_dsm_operation...");
        let new_state = self.core_sdk.execute_dsm_operation(op)?;
        log::debug!("[TOKEN] execute_signed_transfer: execute_dsm_operation OK");

        self.project_balance_cache_from_state(sender, &new_state)?;
        log::debug!("[TOKEN] execute_signed_transfer: local cache projected");

        // Record history in local cache
        {
            let recipient_bytes: [u8; 32] =
                crate::util::domain_helpers::device_id_hash(recipient.as_str());
            let token_op = TokenOperation::Transfer {
                token_id: token_id.clone(),
                recipient: recipient_bytes,
                amount,
                memo,
            };
            let mut history = self.transaction_history.write();
            history.push((token_op, crate::util::deterministic_time::tick()));
        }

        Ok(new_state)
    }

    /// Execute a pre-built, pre-signed Transfer Operation directly through the state machine.
    /// This avoids the signature-verification mismatch caused by `execute_signed_transfer`
    /// reconstructing a different Operation than the one originally signed.
    pub fn execute_transfer_op(&self, op: Operation) -> Result<State, DsmError> {
        // Extract fields for balance cache updates before consuming the operation
        let (token_id, amount_val, recipient_device_id, memo) = match &op {
            Operation::Transfer {
                token_id,
                amount,
                to_device_id,
                message,
                ..
            } => (
                String::from_utf8_lossy(token_id).into_owned(),
                amount.value(),
                to_device_id.clone(),
                Some(message.clone()),
            ),
            _ => {
                return Err(DsmError::invalid_operation(
                    "execute_transfer_op requires a Transfer operation",
                ))
            }
        };

        let current_state = self.core_sdk.get_current_state()?;
        let sender = current_state.device_info.device_id;

        log::debug!("[TOKEN] execute_transfer_op: calling core_sdk.execute_dsm_operation...");
        let new_state = self.core_sdk.execute_dsm_operation(op)?;
        log::debug!("[TOKEN] execute_transfer_op: execute_dsm_operation OK");

        log::debug!("[TOKEN] execute_transfer_op: projecting local cache from canonical state...");
        self.project_balance_cache_from_state(sender, &new_state)?;
        log::debug!("[TOKEN] execute_transfer_op: local cache projected");

        // Record history
        {
            let recipient_bytes: [u8; 32] = if recipient_device_id.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&recipient_device_id);
                arr
            } else {
                crate::util::domain_helpers::device_id_hash_bytes(&recipient_device_id)
            };
            let token_op = TokenOperation::Transfer {
                token_id,
                recipient: recipient_bytes,
                amount: amount_val,
                memo,
            };
            let mut history = self.transaction_history.write();
            history.push((token_op, crate::util::deterministic_time::tick()));
        }

        Ok(new_state)
    }
}

impl Default for GenesisStateCache {
    fn default() -> Self {
        Self::new()
    }
}

impl GenesisStateCache {
    pub fn new() -> Self {
        Self {
            genesis_states: Arc::new(RwLock::new(HashMap::new())),
            verified_states: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn fetch_and_cache_genesis(&self, device_id: &str) -> Result<GenesisState, DsmError> {
        {
            let states = self.genesis_states.read();
            if let Some(genesis) = states.get(device_id) {
                return Ok(genesis.clone());
            }
        }

        log::info!("Fetching Genesis state for {device_id} from storage nodes");
        let genesis = fetch_genesis_state(device_id, "").await?;

        let verification_result = verify_genesis_state(&genesis)?;

        if !verification_result {
            return Err(DsmError::invalid_operation(
                "Genesis state verification failed",
            ));
        }

        {
            let mut states = self.genesis_states.write();
            let mut verified = self.verified_states.write();

            states.insert(device_id.to_string(), genesis.clone());
            verified.insert(device_id.to_string(), true);
        }

        Ok(genesis)
    }

    pub fn has_verified_genesis(&self, device_id: &str) -> bool {
        let verified = self.verified_states.read();
        verified.get(device_id).copied().unwrap_or(false)
    }

    pub fn get_cached_genesis(&self, device_id: &str) -> Option<GenesisState> {
        let states = self.genesis_states.read();
        states.get(device_id).cloned()
    }
}

// Implement TokenManagerTrait for TokenSDK
impl TokenManagerTrait for TokenSDK<IdentitySDK> {
    fn register_token(&self, token_id: &str) -> Result<(), DsmError> {
        if self.resolve_token_metadata_strict(token_id)?.is_none() {
            return Err(DsmError::invalid_operation(format!(
                "Cannot register token {token_id} without canonical metadata"
            )));
        }

        log::info!("Registered token: {token_id}");
        Ok(())
    }

    fn get_balance(&self, token_id: &str) -> Result<u64, DsmError> {
        let device_id = self.device_id;
        let balances = self.balances.read();
        if let Some(device_balances) = balances.get(&device_id) {
            if let Some(balance) = device_balances.get(token_id) {
                return Ok(balance.value());
            }
        }
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::types::{
        operations::Operation,
        state_types::{DeviceInfo, State, StateParams},
    };

    fn build_state(
        device_info: DeviceInfo,
        state_number: u64,
        balances: &[(&str, Balance)],
        operation: Operation,
    ) -> State {
        let mut state = State::new(StateParams::new(
            state_number,
            vec![state_number as u8; 32],
            operation,
            device_info,
        ));
        state.hash = [state_number as u8; 32];
        for (token_id, balance) in balances {
            state
                .token_balances
                .insert((*token_id).to_string(), balance.clone());
        }
        state
    }

    #[test]
    fn reload_balance_cache_for_self_projects_from_current_state() {
        let device_info = DeviceInfo::from_hashed_label("projection-reload", vec![7u8; 32]);
        let core_sdk = Arc::new(
            CoreSDK::new_with_device(device_info.clone())
                .expect("CoreSDK should initialize for projection test"),
        );
        let sdk: TokenSDK<()> = TokenSDK::new(core_sdk.clone(), device_info.device_id);
        let canonical_balance = Balance::from_state(100, [7u8; 32], 7);
        let state = build_state(
            device_info.clone(),
            7,
            &[("ERA", canonical_balance.clone())],
            Operation::Generic {
                operation_type: b"noop".to_vec(),
                data: Vec::new(),
                message: "noop".to_string(),
                signature: Vec::new(),
            },
        );
        core_sdk
            .restore_state_snapshot(&state)
            .expect("state snapshot restore should succeed");

        sdk.balances.write().insert(
            device_info.device_id,
            HashMap::from([("ERA".to_string(), Balance::from_state(1, [1u8; 32], 1))]),
        );

        sdk.reload_balance_cache_for_self(device_info.device_id)
            .expect("reload should project from canonical state");

        let cached = sdk
            .balances
            .read()
            .get(&device_info.device_id)
            .and_then(|balances| balances.get("ERA"))
            .cloned()
            .expect("ERA balance should exist after projection");
        assert_eq!(cached, canonical_balance);
    }

    #[test]
    fn project_balance_cache_from_state_replaces_stale_tokens_on_non_token_transition() {
        let device_info = DeviceInfo::from_hashed_label("projection-generic", vec![9u8; 32]);
        let core_sdk = Arc::new(
            CoreSDK::new_with_device(device_info.clone())
                .expect("CoreSDK should initialize for generic projection test"),
        );
        let sdk: TokenSDK<()> = TokenSDK::new(core_sdk, device_info.device_id);
        sdk.balances.write().insert(
            device_info.device_id,
            HashMap::from([
                ("ERA".to_string(), Balance::from_state(3, [3u8; 32], 3)),
                ("dBTC".to_string(), Balance::from_state(9, [3u8; 32], 3)),
            ]),
        );

        let carried_forward = Balance::from_state(55, [8u8; 32], 8);
        let generic_state = build_state(
            device_info.clone(),
            8,
            &[("ERA", carried_forward.clone())],
            Operation::Generic {
                operation_type: b"noop".to_vec(),
                data: Vec::new(),
                message: "non-token state advance".to_string(),
                signature: Vec::new(),
            },
        );

        sdk.project_balance_cache_from_state(device_info.device_id, &generic_state)
            .expect("projection from carried-forward state should succeed");

        let cached = sdk
            .balances
            .read()
            .get(&device_info.device_id)
            .cloned()
            .expect("device cache should exist after projection");
        assert_eq!(cached.len(), 1);
        assert_eq!(cached.get("ERA"), Some(&carried_forward));
        assert!(!cached.contains_key("dBTC"));
    }

    #[test]
    fn classify_token_dbtc() {
        assert_eq!(classify_token("dBTC"), TokenLane::Dbtc);
    }

    #[test]
    fn classify_token_era_is_canonical() {
        assert_eq!(classify_token("ERA"), TokenLane::Canonical);
    }

    #[test]
    fn classify_token_arbitrary_is_canonical() {
        assert_eq!(classify_token("MyToken"), TokenLane::Canonical);
        assert_eq!(classify_token(""), TokenLane::Canonical);
    }

    #[test]
    fn canonical_token_id_from_balance_key_era() {
        assert_eq!(canonical_token_id_from_balance_key("ERA"), Some("ERA"));
    }

    #[test]
    fn canonical_token_id_from_balance_key_pipe_format() {
        assert_eq!(
            canonical_token_id_from_balance_key("prefix|MyToken"),
            Some("MyToken")
        );
    }

    #[test]
    fn canonical_token_id_from_balance_key_empty_after_pipe() {
        assert_eq!(canonical_token_id_from_balance_key("prefix|"), None);
    }

    #[test]
    fn canonical_token_id_from_balance_key_no_pipe() {
        assert_eq!(canonical_token_id_from_balance_key("random"), None);
    }

    #[test]
    fn encode_embedded_proof_roundtrip() {
        let pk = vec![1u8; 33];
        let sig = vec![2u8; 64];
        let proof = encode_embedded_proof(&pk, &sig).unwrap();

        let pk_len = u16::from_le_bytes([proof[0], proof[1]]) as usize;
        assert_eq!(pk_len, 33);
        assert_eq!(&proof[2..2 + pk_len], &pk[..]);
        let sig_offset = 2 + pk_len;
        let sig_len = u16::from_le_bytes([proof[sig_offset], proof[sig_offset + 1]]) as usize;
        assert_eq!(sig_len, 64);
        assert_eq!(&proof[sig_offset + 2..], &sig[..]);
    }

    #[test]
    fn encode_embedded_proof_rejects_oversized_key() {
        let pk = vec![0u8; u16::MAX as usize + 1];
        let sig = vec![0u8; 1];
        assert!(encode_embedded_proof(&pk, &sig).is_err());
    }

    #[test]
    fn token_type_roundtrip() {
        let types = [
            TokenType::Native,
            TokenType::Created,
            TokenType::Restricted,
            TokenType::Wrapped,
        ];
        for tt in &types {
            let serialized = token_type_to_string(tt);
            let deserialized = token_type_from_string(&serialized);
            assert_eq!(&deserialized, tt);
        }
    }

    #[test]
    fn token_type_from_string_unknown_defaults_to_created() {
        assert_eq!(token_type_from_string("UNKNOWN"), TokenType::Created);
        assert_eq!(token_type_from_string(""), TokenType::Created);
    }

    #[test]
    fn token_type_from_string_case_insensitive() {
        assert_eq!(token_type_from_string("native"), TokenType::Native);
        assert_eq!(token_type_from_string("Wrapped"), TokenType::Wrapped);
    }

    #[test]
    fn map_to_metadata_fields_deterministic_order() {
        let mut metadata = HashMap::new();
        metadata.insert("z_key".into(), "z_val".into());
        metadata.insert("a_key".into(), "a_val".into());
        metadata.insert("m_key".into(), "m_val".into());

        let fields = map_to_metadata_fields(&metadata);
        assert_eq!(fields.len(), 3);
        assert_eq!(fields[0].key, "a_key");
        assert_eq!(fields[1].key, "m_key");
        assert_eq!(fields[2].key, "z_key");
    }

    #[test]
    fn metadata_fields_roundtrip() {
        let mut metadata = HashMap::new();
        metadata.insert("version".into(), "1.0".into());
        metadata.insert("author".into(), "test".into());

        let fields = map_to_metadata_fields(&metadata);
        let back = metadata_fields_to_map(&fields);
        assert_eq!(metadata, back);
    }

    #[test]
    fn era_token_new_has_expected_fields() {
        let era = EraToken::new(1_000_000);
        assert_eq!(era.token_id, "ERA");
        assert_eq!(era.metadata.symbol, "ERA");
        assert_eq!(era.metadata.decimals, 18);
        assert_eq!(era.metadata.token_type, TokenType::Native);
        assert_eq!(era.total_supply.value(), 1_000_000);
        assert!(era.fee_schedule.contains_key("token_creation"));
        assert!(era.fee_schedule.contains_key("smart_commitment"));
    }

    #[test]
    fn locked_balance_entry_protobuf_roundtrip() {
        let entry = LockedBalanceEntry {
            key: "dev1:ERA:lock".into(),
            amount: 42,
        };
        let bytes = entry.encode_to_vec();
        let decoded = LockedBalanceEntry::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded.key, "dev1:ERA:lock");
        assert_eq!(decoded.amount, 42);
    }

    #[test]
    fn transfer_record_protobuf_roundtrip() {
        let rec = TransferRecord {
            token_id: "ERA".into(),
            from_device_id: "alice".into(),
            to_device_id: "bob".into(),
            amount: 100,
            memo: Some("test transfer".into()),
            state_number: 5,
            tick: 99,
        };
        let bytes = rec.encode_to_vec();
        let decoded = TransferRecord::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded.token_id, "ERA");
        assert_eq!(decoded.amount, 100);
        assert_eq!(decoded.memo.as_deref(), Some("test transfer"));
        assert_eq!(decoded.state_number, 5);
        assert_eq!(decoded.tick, 99);
    }
}
