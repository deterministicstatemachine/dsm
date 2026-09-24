// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Token SDK Module (protobuf-only, deterministic)
//!
//! Protobuf-only encoding (prost::Message). No serde/JSON, no bincode.
//! Deterministic preimages are constructed manually for hashing.
//!
//! Replaces any JSON-based parameter parsing (e.g., locked balances) with
//! protobuf messages and removes any `bincode` serialization from preimages.

use std::{collections::HashMap, sync::Arc};

use dsm::{
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

use super::core_sdk::{CoreSDK, Operation as CoreOperation};

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
            // Reads the CORE constant: the conservation guard validates this
            // exact value, so a schedule that could disagree with it would be a
            // second authority over a protocol rule.
            Balance::amount(dsm::core::token::TOKEN_CREATION_FEE_ERA),
        );
        fee_schedule.insert("token_update".to_string(), Balance::zero());
        fee_schedule.insert("token_transfer".to_string(), Balance::zero());
        fee_schedule.insert("token_burn".to_string(), Balance::zero());
        fee_schedule.insert("subscription_base".to_string(), Balance::zero());
        fee_schedule.insert("state_transition".to_string(), Balance::zero());
        fee_schedule.insert("smart_commitment".to_string(), Balance::amount(2));
        fee_schedule.insert("storage_tier_1gb".to_string(), Balance::amount(5));
        fee_schedule.insert("storage_tier_10gb".to_string(), Balance::amount(25));
        fee_schedule.insert("storage_tier_100gb".to_string(), Balance::amount(100));
        fee_schedule.insert("storage_tier_1tb".to_string(), Balance::amount(500));
        fee_schedule.insert("storage_tier_unlimited".to_string(), Balance::amount(2000));

        let metadata = TokenMetadata {
            name: "ERA".to_string(),
            symbol: "ERA".to_string(),
            description: Some("Resilient Oracle-Optimized Trustless token - the native token of the DSM ecosystem".to_string()),
            icon_url: None,
            // ERA is whole-unit. The display path, the faucet and the fee
            // schedule all treat it as 0 decimals; carrying 18 here was a
            // second, contradicting answer that would mis-scale the fee
            // display by 10^18 the moment anything read it.
            decimals: 0,
            fields,
            token_id: "ERA".to_string(),
            token_type: TokenType::Native,
            owner_id: *dsm::crypto::blake3::domain_hash(dsm::common::domain_tags::TAG_DSM_SYSTEM_OWNER, b"").as_bytes(),
            metadata_uri: None,
            policy_anchor: builtin_policy_anchor_uri("ERA"),
        };

        Self {
            token_id: "ERA".to_string(),
            metadata,
            status: TokenStatus::Active,
            total_supply: Balance::amount(total_supply),
            circulating_supply: Balance::zero(),
            fee_schedule,
        }
    }
}

// ---------- Token SDK ----------

pub struct TokenSDK {
    core_sdk: Arc<CoreSDK>,
    token_metadata: Arc<RwLock<HashMap<String, TokenMetadata>>>,
    era_token: Arc<RwLock<EraToken>>,
    balances: Arc<RwLock<HashMap<DevId, HashMap<String, Balance>>>>,
}

impl TokenSDK {
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

    /// Resolve a token identity from the durable registry, accepting either the
    /// canonical token id or a registered ticker.
    ///
    /// The registry is authoritative for the persisted identity mapping —
    /// token_id, policy_commit, ticker, decimals, metadata. (Canonical
    /// DeviceState remains authoritative for balances and transitions; this
    /// answers "which asset", never "how much".)
    ///
    /// The live path resolved from the BCR archive instead, and on hardware a
    /// send of a token the device had just created failed with
    /// "Token metadata for RIGB not found in archived chain states". Two
    /// reasons, either sufficient: the registry probe only ever looked up by
    /// token id while the UI supplies a TICKER, and the archive matcher knew
    /// `Operation::Create` but not `Operation::CreateToken`, which is what
    /// creation actually emits now. So the archive could not match, and the
    /// registry was never asked the question it could answer.
    ///
    /// Archive scanning is also the wrong instrument here. `get_bcr_chain_states`
    /// SKIPS rows it cannot decode, so damaged history degrades into "token not
    /// found" — a lookup miss that reads like the token never existed. And an
    /// ADOPTED token has no creator-side `CreateToken` in this device's archive
    /// at all, so no amount of scanning would ever find it. Reconstructing the
    /// registry from the chain is a legitimate but SEPARATE recovery operation
    /// that must fail loudly on undecodable rows; it is not a fallback for a
    /// send.
    fn resolve_registered_token(
        &self,
        identifier: &str,
    ) -> Result<crate::storage::client_db::token_registry::TokenRegistryRow, DsmError> {
        let id = identifier.trim();
        if id.is_empty() {
            return Err(DsmError::state("token identifier is empty"));
        }
        if let Ok(Some(row)) = crate::storage::client_db::token_registry::get_token(id) {
            return Ok(row);
        }
        if let Ok(Some(row)) = crate::storage::client_db::token_registry::get_token_by_ticker(id) {
            return Ok(row);
        }
        Err(DsmError::state(format!(
            "{id} is not a registered token on this device — create it, or add it by its CPTA \
             anchor before using it"
        )))
    }

    /// Locate the operation that registered metadata for `token_id` by
    /// scanning the per-relationship chain-state archive in newest-first
    /// order (§2.2/§4.3 — no counters, no state_number; the archive is
    /// keyed by chain tip and ordered by insertion time).
    ///
    /// `Ok(None)` only when the whole archive was read and names no such
    /// token; a read or decode failure is an error, never "not found".
    fn find_token_metadata_operation(&self, token_id: &str) -> Result<Option<Operation>, DsmError> {
        let device_id = self.core_sdk.get_current_state()?.device_info.device_id;
        let states =
            crate::storage::client_db::get_bcr_chain_states(&device_id, false).map_err(|e| {
                DsmError::storage(
                    format!("Failed to load BCR chain states for token metadata lookup: {e}"),
                    None::<std::io::Error>,
                )
            })?;
        Ok(states
            .into_iter()
            .rev()
            .map(|state| state.operation)
            .find(|operation| Self::operation_carries_token_metadata(operation, token_id)))
    }

    fn operation_carries_token_metadata(op: &Operation, token_id: &str) -> bool {
        match op {
            Operation::Create { metadata, .. } => {
                if metadata.is_empty() {
                    return false;
                }
                if let Ok(proto) = TokenMetadataProto::decode(metadata.as_slice()) {
                    return proto.token_id == token_id || proto.symbol == token_id;
                }
                false
            }
            Operation::Generic {
                operation_type,
                data,
                ..
            } => {
                if operation_type.as_slice() != b"token_create"
                    && operation_type.as_slice() != b"token_registry_update"
                {
                    return false;
                }
                if let Ok(registry_update) = decode_registry_update(data) {
                    return registry_update.contains_key(token_id);
                }
                if let Ok(single) = TokenMetadataProto::decode(data.as_slice()) {
                    return single.token_id == token_id || single.symbol == token_id;
                }
                false
            }
            _ => false,
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

        // Durable registry. The in-memory metadata map is dropped on process
        // exit, so without this a token created before a restart could not be
        // resolved at all — which fails closed in the send path and in
        // `dlv.create`, making the token unusable rather than merely invisible.
        // Registry is authoritative for token identity, and accepts either the
        // canonical id or a registered ticker — which is what the send form
        // supplies. No archive scan on the live path: see
        // resolve_registered_token for why that was both wrong and unusable
        // for adopted tokens.
        self.resolve_registered_token(token_id)
            .map(|row| row.policy_commit)
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
            Ok(Some(record)) => match balance_from_projection(&record) {
                Ok(balance) => return Some(balance),
                Err(e) => {
                    log::warn!(
                        "[TokenSDK] Ignoring invalid projection row for {}: {}",
                        token_id,
                        e
                    );
                }
            },
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
                state.hash[0] as u64,
            );
        }
        balances.insert(device_id, projected);
        Ok(())
    }

    pub(crate) fn cache_token_metadata_strict(
        &self,
        mut metadata: TokenMetadata,
    ) -> Result<TokenMetadata, DsmError> {
        if let Some(policy_anchor) = builtin_policy_anchor_uri(&metadata.token_id) {
            metadata.policy_anchor = Some(policy_anchor);
        }

        let policy_commit = crate::policy::strict_policy_commit_for_token(
            &metadata.token_id,
            metadata.policy_anchor.as_deref(),
        )?;

        // Teach core how to NAME this token's balances. Core owns the
        // compatibility projection but cannot see this registry, so without
        // this every created token's balance is unnameable and therefore
        // omitted from the projection. Display-only: `policy_commit` remains
        // the canonical key.
        dsm::core::token::register_policy_commit_ticker(policy_commit, &metadata.symbol);

        self.token_metadata
            .write()
            .insert(metadata.token_id.clone(), metadata.clone());

        Ok(metadata)
    }

    pub fn new(core_sdk: Arc<CoreSDK>) -> Self {
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
        }
    }

    /// Sign a transfer operation by clearing the signature field and applying the
    /// device's SPHINCS+ secret key. Returns a descriptive error if the key has
    /// not been registered yet.
    fn sign_transfer_operation(&self, op: &Operation) -> Result<Vec<u8>, DsmError> {
        let signing_key = crate::sdk::signing_authority::current_secret_key()?;

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

    pub async fn execute_token_operation(
        &self,
        operation: TokenOperation,
    ) -> Result<State, DsmError> {
        self.validate_token_operation(&operation)?;
        self.execute_generic_token_operation(&operation).await
    }

    async fn execute_generic_token_operation(
        &self,
        operation: &TokenOperation,
    ) -> Result<State, DsmError> {
        match operation {
            TokenOperation::Transfer {
                token_id,
                recipient,
                amount,
                ..
            } => {
                let sender = self.core_sdk.get_current_state()?.device_info.device_id;

                let policy_commit = self.resolve_policy_commit_strict(token_id)?;
                let mut op = Operation::Transfer {
                    to_device_id: recipient.to_vec(),
                    amount: Balance::amount(*amount),
                    token_id: token_id.as_bytes().to_vec(),
                    policy_commit,
                    mode: TransactionMode::Bilateral,
                    nonce: Vec::new(),
                    verification: VerificationType::Standard,
                    pre_commit: None,
                    message: "Transfer operation via TokenSDK".to_string(),
                    recipient: recipient.to_vec(),
                    to: crate::util::text_id::encode_base32_crockford(recipient).into_bytes(),
                    signature: Vec::new(),
                    authority_policy: None,
                };

                let signature = self.sign_transfer_operation(&op)?;
                if let Operation::Transfer { signature: sig, .. } = &mut op {
                    *sig = signature;
                }

                // Route via relationship-aware path (§2.2)
                let rel_key =
                    dsm::core::bilateral_transaction_manager::compute_smt_key(&sender, recipient);
                let pc = self.resolve_policy_commit_strict(token_id)?;
                let deltas = [dsm::types::device_state::BalanceDelta {
                    policy_commit: pc,
                    direction: dsm::types::device_state::BalanceDirection::Debit,
                    amount: *amount,
                }];
                let (new_state, _) = self
                    .core_sdk
                    .execute_on_relationship(rel_key, *recipient, op, &deltas)?;
                self.project_balance_cache_from_state(sender, &new_state)?;

                Ok(new_state)
            }
            TokenOperation::Mint { token_id, .. } => {
                // OWNER RULING (0x0029 producer cut): token.mint is the ONE
                // mint producer. This surface used to sign the legacy
                // `mint|v2|` self-authorization and advance a raw credit via
                // `execute_on_relationship` — a positive mint with NO economic
                // admission, which the accepting layer refuses since the
                // producer cut. Its remaining caller chain is the Bitcoin/dBTC
                // deposit completion, and dBTC is a BUILTIN whose issuance is
                // not self-authorizable at all: that success path was already
                // structurally impossible, and it becomes honest here. dBTC
                // issuance into R_econ arrives with the Bitcoin tap
                // integration; user-token issuance goes through `token.mint`.
                Err(DsmError::invalid_operation(format!(
                    "TokenSDK mint of {token_id} is not a producer: a positive mint enters \
                     canonical state only through token.mint's economic admission, whose \
                     0x0029 issuance evidence a verifier reruns — and builtin dBTC issuance \
                     arrives with the Bitcoin tap integration"
                )))
            }
            TokenOperation::Burn {
                token_id, amount, ..
            } => {
                // 3.5b HARD REFUSAL (owner correction D): once an economic
                // lineage exists, an UNADMITTED local burn on this path
                // (reachable from the Bitcoin/dBTC withdrawal routes) would
                // leave the validated R_econ value intact for an adversarial
                // producer while the external side effect proceeds. The
                // admitted burn path is `token.burn`; this surface's
                // admission integration lands with the DLV economic cut.
                // Never a documented stranding note — a refusal.
                if crate::storage::client_db::economic_lineage::get_admitted()
                    .map_err(|e| {
                        DsmError::storage(
                            format!("admitted coordinate read: {e}"),
                            None::<std::io::Error>,
                        )
                    })?
                    .is_some()
                {
                    return Err(DsmError::invalid_operation(
                        "burn: this identity has an active economic lineage; an unadmitted \
                         burn would desynchronize the validated economic root from local \
                         state — use the admitted burn path (token.burn)",
                    ));
                }
                let owner_id = self.core_sdk.get_current_state()?.device_info.device_id;
                let policy_commit = self.resolve_policy_commit_strict(token_id)?;

                // The burn is authorized by the signer set its policy names:
                // the same witness `token.burn` carries, over the preimage the
                // policy's `TokenAuthority` condition rebuilds from this burn.
                let op = Operation::Burn {
                    amount: Balance::amount(*amount),
                    token_id: token_id.as_bytes().to_vec(),
                    policy_commit,
                    proof_of_ownership: crate::sdk::signing_authority::token_authorization_witness(
                        &policy_commit,
                        "burn",
                        token_id.as_bytes(),
                        *amount,
                        &[],
                    )?,
                    message: "Burn operation via TokenSDK".to_string(),
                };

                // Burn: relationship is device↔self (CPTA authority path)
                let burn_rel_key =
                    dsm::core::bilateral_transaction_manager::compute_smt_key(&owner_id, &owner_id);
                let burn_deltas = [dsm::types::device_state::BalanceDelta {
                    policy_commit,
                    direction: dsm::types::device_state::BalanceDirection::Debit,
                    amount: *amount,
                }];
                let (new_state, _) = self.core_sdk.execute_on_relationship(
                    burn_rel_key,
                    owner_id,
                    op,
                    &burn_deltas,
                )?;
                self.project_balance_cache_from_state(owner_id, &new_state)?;

                if token_id == "ERA" {
                    let mut era_token = self.era_token.write();
                    let new_circulation = Balance::from_state(
                        era_token.circulating_supply.value().saturating_sub(*amount),
                        new_state.hash,
                    );
                    era_token.circulating_supply = new_circulation;
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
                    self.validate_and_charge_fee(&creator_id, *fee).await?;
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
                    amount: Balance::amount(*amount),
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

                Ok(new_state)
            }
        }
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

    fn generate_nonce(&self) -> Vec<u8> {
        dsm::crypto::generate_nonce_32()
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
        let token_balances = crate::storage::client_db::list_balance_projections(&device_id_str)
            .map_err(|e| {
                DsmError::storage(
                    format!("balance projections could not be read: {e}"),
                    None::<std::io::Error>,
                )
            })?;
        for record in token_balances {
            let balance = balance_from_projection(&record)?;
            reloaded.insert(record.token_id, balance);
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
                token_id, amount, ..
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
                token_id, amount, ..
            } => {
                if *amount == 0 {
                    return Err(DsmError::invalid_operation("Amount must be positive"));
                }
                let owner = self.core_sdk.get_current_state()?.device_info.device_id;
                if self.locked_amount(&owner, token_id) < *amount {
                    return Err(DsmError::invalid_operation(
                        "Unlock amount exceeds the token's locked amount",
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

        let TokenSupply::Fixed(amount) = supply;
        if *amount == 0 {
            return Err(DsmError::invalid_operation("Fixed supply cannot be zero"));
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
        let hash = dsm::crypto::blake3::domain_hash(
            dsm::common::domain_tags::TAG_DSM_TOKEN_METADATA,
            &metadata_bytes,
        );
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

        Ok(self.find_token_metadata_operation(token_id)?.is_some())
    }

    async fn validate_and_charge_fee(
        &self,
        _creator_id: &[u8; 32],
        fee: u64,
    ) -> Result<(), DsmError> {
        if fee == 0 {
            return Ok(());
        }

        let current_state = self.core_sdk.get_current_state()?;
        let fee_policy_commit = self.resolve_policy_commit_strict("ERA")?;
        let mut fee_transfer_op = Operation::Transfer {
            to_device_id: b"system.fee.device_id".to_vec(),
            amount: Balance::amount(fee),
            token_id: b"ERA".to_vec(),
            policy_commit: fee_policy_commit,
            mode: TransactionMode::Bilateral,
            nonce: self.generate_nonce(),
            verification: VerificationType::Standard,
            pre_commit: None,
            message: "Fee payment".to_string(),
            recipient: b"system.fee.device_id".to_vec(),
            to: b"system.fee.device_id".to_vec(),
            signature: Vec::new(),
            authority_policy: None,
        };

        let signature = self.sign_transfer_operation(&fee_transfer_op)?;
        if let Operation::Transfer { signature: sig, .. } = &mut fee_transfer_op {
            *sig = signature;
        }

        // Fee: relationship is device↔system.fee (deterministic system counterparty)
        let fee_counterparty = *dsm::crypto::blake3::domain_hash(
            dsm::common::domain_tags::TAG_DSM_SYSTEM_FEE_DEVICE,
            b"system.fee.device_id",
        )
        .as_bytes();
        let fee_rel_key = dsm::core::bilateral_transaction_manager::compute_smt_key(
            &current_state.device_info.device_id,
            &fee_counterparty,
        );
        let era_pc = dsm::core::token::token_state_manager::resolve_policy_commit("ERA")?;
        let fee_deltas = [dsm::types::device_state::BalanceDelta {
            policy_commit: era_pc,
            direction: dsm::types::device_state::BalanceDirection::Debit,
            amount: fee,
        }];
        let (new_state, _) = self.core_sdk.execute_on_relationship(
            fee_rel_key,
            fee_counterparty,
            fee_transfer_op,
            &fee_deltas,
        )?;
        self.project_balance_cache_from_state(current_state.device_info.device_id, &new_state)?;
        Ok(())
    }

    /// The amount of `token_id` locked in this device's balance cache. Locks
    /// are not kept per purpose: this is the token's whole lock.
    fn locked_amount(&self, device_id: &[u8; 32], token_id: &str) -> u64 {
        self.balances
            .read()
            .get(device_id)
            .and_then(|device_balances| device_balances.get(token_id))
            .map_or(0, Balance::locked)
    }

    /// [`Self::execute_transfer_op_staged`] with an economic admission riding
    /// the same advance (3.5b sender debit).
    pub fn execute_transfer_op_staged_with_admission<A>(
        &self,
        op: Operation,
        build_artifacts: impl FnOnce(&dsm::types::device_state::AdvanceOutcome) -> Result<A, DsmError>,
        write_extra: impl Fn(
            &rusqlite::Transaction<'_>,
            &dsm::types::device_state::AdvanceOutcome,
            &A,
        ) -> Result<(), DsmError>,
        admission: Option<crate::sdk::core_sdk::AdmissionPlan<'_>>,
    ) -> Result<(State, A), DsmError> {
        // Extract fields for balance cache updates before consuming the operation
        let (token_id, amount_val, recipient_device_id) = match &op {
            Operation::Transfer {
                token_id,
                amount,
                to_device_id,
                ..
            } => (
                String::from_utf8_lossy(token_id).into_owned(),
                amount.value(),
                to_device_id.clone(),
            ),
            _ => {
                return Err(DsmError::invalid_operation(
                    "execute_transfer_op requires a Transfer operation",
                ))
            }
        };

        let current_state = self.core_sdk.get_current_state()?;
        let sender = current_state.device_info.device_id;

        // Route through relationship-aware path (§2.2, §4.2)
        let recipient_devid =
            <[u8; 32]>::try_from(recipient_device_id.as_slice()).map_err(|_| {
                DsmError::invalid_operation(format!(
                    "a transfer names its recipient by a 32-byte device id, not {} bytes",
                    recipient_device_id.len()
                ))
            })?;
        let rel_key =
            dsm::core::bilateral_transaction_manager::compute_smt_key(&sender, &recipient_devid);
        let policy_commit = self.resolve_policy_commit_strict(&token_id)?;
        let deltas = [dsm::types::device_state::BalanceDelta {
            policy_commit,
            direction: dsm::types::device_state::BalanceDirection::Debit,
            amount: amount_val,
        }];
        log::debug!("[TOKEN] execute_transfer_op: calling execute_on_relationship...");
        let staged = self
            .core_sdk
            .execute_on_relationship_staged_with_admission(
                rel_key,
                recipient_devid,
                op,
                &deltas,
                build_artifacts,
                write_extra,
                admission,
            )?;
        log::debug!("[TOKEN] execute_transfer_op: execute_on_relationship OK");
        let new_state = staged.state;

        // Post-commit: in-memory cache projection only. The advance and the durable
        // bundle committed inside `execute_on_relationship_staged`, so returning Err
        // here would tell the caller "nothing happened" about a committed,
        // deliverable transfer. The cache rebuilds via `reload_balance_cache_for_self`.
        log::debug!("[TOKEN] execute_transfer_op: projecting local cache from canonical state...");
        if let Err(e) = self.project_balance_cache_from_state(sender, &new_state) {
            log::error!(
                "[TOKEN] execute_transfer_op: post-commit cache projection FAILED ({e}). \
                 The transfer stands."
            );
            // Durable reconcile-forward: the in-memory cache is rebuilt on the
            // next load, but persist the intent so a crash cannot lose it.
            if let Err(q) = crate::storage::client_db::enqueue_projection_repair(
                &crate::util::text_id::encode_base32_crockford(&sender),
                &token_id,
                &format!("post-commit cache projection failed: {e}"),
            ) {
                log::error!("[TOKEN] execute_transfer_op: could not QUEUE cache repair: {q}");
            }
        }
        log::debug!("[TOKEN] execute_transfer_op: local cache projected");

        Ok((new_state, staged.artifacts))
    }
}

/// A balance projection row as a balance: the state it was derived from and
/// its lock. A row whose source state hash is not 32 bytes of Base32, or whose
/// lock exceeds what it holds, is not a balance.
fn balance_from_projection(
    record: &crate::storage::client_db::BalanceProjectionRecord,
) -> Result<Balance, DsmError> {
    let source_state_hash =
        crate::util::text_id::decode_base32_crockford(&record.source_state_hash)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .ok_or_else(|| {
                DsmError::invalid_parameter(format!(
                    "balance projection for {}: the source state hash is not 32 bytes of Base32",
                    record.token_id
                ))
            })?;
    let mut balance = Balance::from_state(record.available, source_state_hash);
    if record.locked > 0 {
        balance.lock(record.locked)?;
    }
    Ok(balance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::types::{
        operations::Operation,
        state_types::{DeviceInfo, State, StateParams},
    };

    /// Whether a token exists is answered only by a complete read of the
    /// archive: an archive that does not load is an error, never "no such
    /// token" — which would let a creation pass its duplicate check.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_token_lookup_over_an_unreadable_archive_is_an_error_not_absence() {
        let wallet = crate::sdk::wallet_sdk::WalletSDK::test_wallet().expect("wallet");
        assert!(
            !wallet
                .token_sdk
                .token_exists("NOSUCH")
                .await
                .expect("a clean archive reads"),
            "a complete read that names no such token is absence"
        );

        let device_id = wallet
            .token_sdk
            .core_sdk
            .get_current_state()
            .expect("state")
            .device_info
            .device_id;
        {
            let binding = crate::storage::client_db::get_connection().expect("connection");
            let conn = binding.lock().unwrap_or_else(|p| p.into_inner());
            conn.execute(
                "INSERT INTO bcr_chain_states
                   (device_id, rel_key, chain_tip, embedded_parent, state_bytes, published)
                 VALUES (?1, ?2, ?3, ?4, X'00', 0)",
                rusqlite::params![
                    device_id.as_slice(),
                    [0x71u8; 32].as_slice(),
                    [0x72u8; 32].as_slice(),
                    [0x73u8; 32].as_slice(),
                ],
            )
            .expect("an undecodable archived row");
        }
        assert!(
            wallet.token_sdk.token_exists("NOSUCH").await.is_err(),
            "an archive that does not load answers nothing"
        );
    }

    fn projection_row(
        source_state_hash: String,
        available: u64,
        locked: u64,
    ) -> crate::storage::client_db::BalanceProjectionRecord {
        crate::storage::client_db::BalanceProjectionRecord {
            balance_key: "key".into(),
            device_id: "device".into(),
            token_id: "ERA".into(),
            policy_commit: "commit".into(),
            available,
            locked,
            source_state_hash,
        }
    }

    /// A projection row is a balance only with the 32-byte state it was
    /// derived from and a lock it can hold; nothing stands in for either.
    #[test]
    fn a_projection_row_without_its_source_state_or_with_an_unholdable_lock_is_no_balance() {
        let source = [0x3Cu8; 32];
        let source_b32 = crate::util::text_id::encode_base32_crockford(&source);

        let balance = balance_from_projection(&projection_row(source_b32.clone(), 100, 40))
            .expect("a well-formed row");
        assert_eq!(balance.state_hash(), Some(source));
        assert_eq!(balance.locked(), 40);

        let short = crate::util::text_id::encode_base32_crockford(&source[..31]);
        assert!(balance_from_projection(&projection_row(short, 100, 0)).is_err());
        assert!(balance_from_projection(&projection_row("not base32!".into(), 100, 0)).is_err());
        assert!(balance_from_projection(&projection_row(source_b32, 100, 101)).is_err());
    }

    fn build_state(
        device_info: DeviceInfo,
        seed: u64,
        balances: &[(&str, Balance)],
        operation: Operation,
    ) -> State {
        let mut state = State::new(StateParams::new(
            vec![seed as u8; 32],
            operation,
            device_info,
        ));
        state.hash = [seed as u8; 32];
        for (token_id, balance) in balances {
            state
                .token_balances
                .insert((*token_id).to_string(), balance.clone());
        }
        state
    }

    #[test]
    fn project_balance_cache_from_state_replaces_stale_tokens_on_non_token_transition() {
        let device_info = DeviceInfo::from_hashed_label("projection-generic", vec![9u8; 32]);
        let core_sdk = Arc::new(
            CoreSDK::new_with_device(device_info.clone())
                .expect("CoreSDK should initialize for generic projection test"),
        );
        let sdk = TokenSDK::new(core_sdk);
        sdk.balances.write().insert(
            device_info.device_id,
            HashMap::from([
                ("ERA".to_string(), Balance::from_state(3, [3u8; 32])),
                ("dBTC".to_string(), Balance::from_state(9, [3u8; 32])),
            ]),
        );

        let carried_forward = Balance::from_state(55, [8u8; 32]);
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
        // ERA is whole-unit everywhere that reads it — the display path, the
        // faucet and the fee schedule. This pins the ONE answer.
        assert_eq!(era.metadata.decimals, 0);
        assert_eq!(era.metadata.token_type, TokenType::Native);
        assert_eq!(era.total_supply.value(), 1_000_000);
        // The fee is the core constant, not a number this map may invent.
        assert_eq!(
            era.fee_schedule
                .get("token_creation")
                .expect("token_creation fee present")
                .value(),
            dsm::core::token::TOKEN_CREATION_FEE_ERA,
        );
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
}
