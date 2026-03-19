//! DSM specification schema definitions
//!
//! Defines YAML-deserializable input types for DSM vault and policy specs.
//! `FulfillmentConditionSpec` mirrors the `FulfillmentMechanism` oneof in
//! `proto/dsm_app.proto` exactly.  When protoc is available at build time,
//! a `From<FulfillmentConditionSpec>` impl is compiled against the prost-
//! generated proto types — any structural drift causes a *compile error*.
//!
//! ## No wall-clock time (Invariant #4)
//! `TimeoutConfig` / `TimeDelayedRecovery` are removed.  Use `TickLockConfig`
//! with `duration_iterations` (deterministic chain-tick count).
//!
//! ## No serde_json::Value (Invariant #2)
//! All parameter fields use strongly-typed structs or `HashMap<String, String>`.
//!
//! ## Bytes at string boundaries (Invariant #3)
//! Binary fields (keys, hashes, pubkeys) are `String` in YAML; callers must
//! encode them as Base32 Crockford.

// When build.rs compiled the proto successfully, include the prost-generated
// module so the From impl below can enforce structural parity at compile time.
#[cfg(dsm_proto_compiled)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/dsm.rs"));
}

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Top-level spec discriminant
// ---------------------------------------------------------------------------

/// Top-level DSM specification — either a vault or a policy.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type")]
pub enum DsmSpecification {
    #[serde(rename = "vault")]
    Vault(VaultSpecification),
    #[serde(rename = "policy")]
    Policy(PolicySpecification),
}

// ---------------------------------------------------------------------------
// Vault specification
// ---------------------------------------------------------------------------

/// Complete specification for a DSM Deterministic Limbo Vault (DLV).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VaultSpecification {
    pub name: String,
    pub version: String,
    pub description: Option<String>,

    /// Fulfillment condition required to unlock this vault.
    /// Mirrors `FulfillmentMechanism` oneof in `dsm_app.proto`.
    pub fulfillment_condition: FulfillmentConditionSpec,

    pub assets: Vec<AssetDefinition>,

    /// Iteration-based expiry lock (clockless — no wall-clock time).
    pub tick_lock: Option<TickLockConfig>,

    pub recovery: Option<RecoveryConfig>,

    /// Arbitrary string metadata (no serde_json::Value).
    pub metadata: Option<HashMap<String, String>>,

    /// Deployment mode: posted (storage nodes) or local (bilateral).
    /// Default: posted. Only used by `dsm-gen compile`.
    pub deployment_mode: Option<DeploymentMode>,

    /// External commitment context strings for atomic grouping (Level 1).
    /// Reserved for Phase 2 program compilation.
    pub external_commits: Option<Vec<String>>,

    /// Pre-commitment fork group name (Level 1).
    /// Reserved for Phase 2 program compilation.
    pub fork_group: Option<String>,
}

// ---------------------------------------------------------------------------
// FulfillmentConditionSpec — mirrors proto::FulfillmentMechanism oneof
// ---------------------------------------------------------------------------

/// YAML-deserializable mirror of `FulfillmentMechanism` in `dsm_app.proto`.
///
/// Proto tag 1 (`time_release`) is intentionally absent — DSM is clockless
/// (Invariant #4).  The `reserved 1` field in the proto matches this absence.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FulfillmentConditionSpec {
    /// proto tag 2
    Payment(PaymentSpec),
    /// proto tag 3
    CryptoCondition(CryptoConditionSpec),
    /// proto tag 4 — k-of-n SPHINCS+ multi-signature
    MultiSignature(MultiSignatureSpec),
    /// proto tag 5 — prior state hash chain position
    StateReference(StateReferenceSpec),
    /// proto tag 6 — random-walk ZK statement
    RandomWalkVerification(RandomWalkSpec),
    /// proto tag 7 — all sub-conditions required (AND)
    And(AndSpec),
    /// proto tag 8 — any sub-condition satisfies (OR)
    Or(OrSpec),
    /// proto tag 9 — dual-hashlock Bitcoin HTLC (dBTC §6.2-6.4)
    BitcoinHtlc(BitcoinHtlcSpec),
}

/// proto: `Payment { amount, token_id, recipient, verification_state }`
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PaymentSpec {
    pub amount: u64,
    pub token_id: String,
    /// Recipient device_id — Base32 Crockford 32-byte identifier.
    pub recipient: String,
    /// Reference state hash — Base32 Crockford encoded BLAKE3-256.
    pub verification_state: String,
}

/// proto: `CryptoCondition { condition_hash, public_params }`
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CryptoConditionSpec {
    /// BLAKE3("DSM/crypto-condition\0" || preimage) — Base32 Crockford.
    pub condition_hash: String,
    /// Public parameters for the verifier — Base32 Crockford.
    pub public_params: String,
}

/// proto: `MultiSignature { public_keys, threshold }`
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MultiSignatureSpec {
    /// SPHINCS+ public keys — each Base32 Crockford encoded.
    pub public_keys: Vec<String>,
    /// Minimum number of valid signatures required.
    pub threshold: u32,
}

/// proto: `StateReference { reference_states, parameters }`
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StateReferenceSpec {
    /// Reference state hashes — each Base32 Crockford encoded BLAKE3-256.
    pub reference_states: Vec<String>,
    /// Verification parameters — Base32 Crockford encoded.
    pub parameters: String,
}

/// proto: `RandomWalkVerification { verification_key, statement }`
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RandomWalkSpec {
    /// Random-walk verification key — Base32 Crockford encoded.
    pub verification_key: String,
    pub statement: String,
}

/// proto: `And { conditions }`
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AndSpec {
    pub conditions: Vec<FulfillmentConditionSpec>,
}

/// proto: `Or { conditions }`
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OrSpec {
    pub conditions: Vec<FulfillmentConditionSpec>,
}

/// proto: `BitcoinHTLC { hash_lock, refund_hash_lock, refund_iterations,
///                       bitcoin_pubkey, expected_btc_amount_sats,
///                       network, min_confirmations }`
///
/// Implements the dBTC "tap" construction (dBTC spec §6.2-6.4).
/// `refund_iterations` is a DSM chain-tick count — no wall-clock time used.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BitcoinHtlcSpec {
    /// SHA256(sk_V) where sk_V = BLAKE3("DSM/dlv-unlock\0"||…) — Base32 Crockford.
    pub hash_lock: String,
    /// SHA256(rk_V) where rk_V = BLAKE3("DSM/dlv-refund\0"||…) — Base32 Crockford.
    pub refund_hash_lock: String,
    /// DSM chain-tick iterations before depositor can reclaim.
    pub refund_iterations: u64,
    /// Counterparty Bitcoin compressed pubkey (33 bytes) — Base32 Crockford.
    pub bitcoin_pubkey: String,
    /// Expected BTC amount in satoshis.
    pub expected_btc_amount_sats: u64,
    /// Bitcoin network selection.
    pub network: BitcoinNetwork,
    /// Minimum confirmation depth (canonical = 100 per dBTC §6.4, §12.1.3).
    pub min_confirmations: u64,
}

/// Bitcoin network — maps to proto `network` uint32: 0=mainnet, 1=testnet, 2=signet.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
}

impl From<BitcoinNetwork> for u32 {
    fn from(n: BitcoinNetwork) -> u32 {
        match n {
            BitcoinNetwork::Mainnet => 0,
            BitcoinNetwork::Testnet => 1,
            BitcoinNetwork::Signet => 2,
        }
    }
}

/// Deployment mode for compiled vault blobs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    /// Published to storage nodes. Creator can go offline.
    Posted,
    /// Local only. Bilateral fulfillment (BLE/QR/NFC).
    Local,
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

/// A token asset held in or released from a vault.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AssetDefinition {
    pub asset_id: String,
    pub amount: u64,
    /// Optional reference state hash for chain-anchored balance.
    /// Base32 Crockford encoded BLAKE3-256.  The SDK derives
    /// `Balance::from_state(amount, hash, state_number)` when set.
    pub chain_state_hash: Option<String>,
    /// Reference state number paired with `chain_state_hash`.
    pub chain_state_number: Option<u64>,
    pub metadata: Option<HashMap<String, String>>,
}

// ---------------------------------------------------------------------------
// Iteration-based lock (clockless replacement for the removed TimeoutConfig)
// ---------------------------------------------------------------------------

/// Vault expiry expressed in deterministic chain-tick iterations.
/// Wall-clock seconds are banned (Invariant #4).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TickLockConfig {
    /// Number of hash-chain iterations before this lock fires.
    pub duration_iterations: u64,
    pub tick_lock_action: TickLockAction,
}

/// Action taken when a tick-lock fires.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TickLockAction {
    ReturnToOwner,
    /// Release to a specific recipient — Base32 Crockford device_id.
    ReleaseToRecipient {
        recipient: String,
    },
    Burn,
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/// Recovery configuration for a vault.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RecoveryConfig {
    pub mechanism: RecoveryMechanism,
}

/// Supported recovery mechanisms.
/// `TimeDelayedRecovery` is intentionally absent — DSM is clockless (Invariant #4).
/// Time-based recovery is replaced by capsule/tombstone in the core library.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RecoveryMechanism {
    MultiSigRecovery {
        required_signatures: u32,
        /// Recovery SPHINCS+ public keys — Base32 Crockford encoded.
        recovery_keys: Vec<String>,
    },
    SocialRecovery {
        /// Trustee device IDs — Base32 Crockford encoded.
        trustees: Vec<String>,
        threshold: u32,
    },
}

// ---------------------------------------------------------------------------
// Policy specification
// ---------------------------------------------------------------------------

/// Complete specification for a DSM Content-Addressed Token Policy (CPTA).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolicySpecification {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub rules: Vec<TransferRule>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TransferRule {
    pub name: String,
    pub condition: RuleCondition,
    pub action: RuleAction,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RuleCondition {
    pub condition_type: ConditionType,
    /// String-keyed parameters — no `serde_json::Value` (Invariant #2).
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum ConditionType {
    #[serde(rename = "amount_limit")]
    AmountLimit,
    #[serde(rename = "iteration_window")]
    IterationWindow,
    #[serde(rename = "whitelist")]
    Whitelist,
    #[serde(rename = "blacklist")]
    Blacklist,
    #[serde(rename = "signature_required")]
    SignatureRequired,
    #[serde(rename = "custom")]
    Custom,
}

/// Rule action.
/// `Delay.iterations` replaces the old `Delay.seconds` — wall-clock delays are
/// banned (Invariant #4).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Deny,
    RequireApproval,
    /// Delay expressed in deterministic chain iterations, not wall-clock seconds.
    Delay {
        iterations: u64,
    },
}

// ---------------------------------------------------------------------------
// Compile-time drift detection (active when protoc is available at build time)
// ---------------------------------------------------------------------------

/// When the proto was compiled at build time, enforce that
/// `FulfillmentConditionSpec` is convertible to the canonical proto type.
/// A structural mismatch causes a compile error — preventing silent drift.
#[cfg(dsm_proto_compiled)]
impl From<FulfillmentConditionSpec> for proto::FulfillmentMechanism {
    fn from(spec: FulfillmentConditionSpec) -> Self {
        use proto::fulfillment_mechanism::Kind;
        let kind = match spec {
            FulfillmentConditionSpec::Payment(p) => Kind::Payment(proto::Payment {
                amount: p.amount,
                token_id: p.token_id,
                recipient: p.recipient,
                verification_state: p.verification_state.into_bytes(),
            }),
            FulfillmentConditionSpec::CryptoCondition(c) => {
                Kind::CryptoCondition(proto::CryptoCondition {
                    condition_hash: c.condition_hash.into_bytes(),
                    public_params: c.public_params.into_bytes(),
                })
            }
            FulfillmentConditionSpec::MultiSignature(m) => {
                Kind::MultiSignature(proto::MultiSignature {
                    public_keys: m.public_keys.into_iter().map(|k| k.into_bytes()).collect(),
                    threshold: m.threshold,
                })
            }
            FulfillmentConditionSpec::StateReference(s) => {
                Kind::StateReference(proto::StateReference {
                    reference_states: s
                        .reference_states
                        .into_iter()
                        .map(|h| h.into_bytes())
                        .collect(),
                    parameters: s.parameters.into_bytes(),
                })
            }
            FulfillmentConditionSpec::RandomWalkVerification(r) => {
                Kind::RandomWalkVerification(proto::RandomWalkVerification {
                    verification_key: r.verification_key.into_bytes(),
                    statement: r.statement,
                })
            }
            FulfillmentConditionSpec::And(a) => Kind::And(proto::And {
                conditions: a.conditions.into_iter().map(Into::into).collect(),
            }),
            FulfillmentConditionSpec::Or(o) => Kind::Or(proto::Or {
                conditions: o.conditions.into_iter().map(Into::into).collect(),
            }),
            FulfillmentConditionSpec::BitcoinHtlc(h) => Kind::BitcoinHtlc(proto::BitcoinHtlc {
                hash_lock: h.hash_lock.into_bytes(),
                refund_hash_lock: h.refund_hash_lock.into_bytes(),
                refund_iterations: h.refund_iterations,
                bitcoin_pubkey: h.bitcoin_pubkey.into_bytes(),
                expected_btc_amount_sats: h.expected_btc_amount_sats,
                network: u32::from(h.network),
                min_confirmations: h.min_confirmations,
            }),
        };
        proto::FulfillmentMechanism { kind: Some(kind) }
    }
}

// ---------------------------------------------------------------------------
// Example constructors (used by CLI `init` and integration tests)
// ---------------------------------------------------------------------------

impl VaultSpecification {
    pub fn example(name: String) -> Self {
        Self {
            name,
            version: "1.0.0".to_string(),
            description: Some("Example DSM Deterministic Limbo Vault".to_string()),
            fulfillment_condition: FulfillmentConditionSpec::MultiSignature(MultiSignatureSpec {
                public_keys: vec![
                    "SIGNER1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    "SIGNER2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    "SIGNER3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                ],
                threshold: 2,
            }),
            assets: vec![AssetDefinition {
                asset_id: "DSM".to_string(),
                amount: 1000,
                chain_state_hash: None,
                chain_state_number: None,
                metadata: None,
            }],
            tick_lock: Some(TickLockConfig {
                duration_iterations: 86400,
                tick_lock_action: TickLockAction::ReturnToOwner,
            }),
            recovery: Some(RecoveryConfig {
                mechanism: RecoveryMechanism::MultiSigRecovery {
                    required_signatures: 2,
                    recovery_keys: vec![
                        "RKEY1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                        "RKEY2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                    ],
                },
            }),
            metadata: None,
            deployment_mode: None,
            external_commits: None,
            fork_group: None,
        }
    }
}

impl PolicySpecification {
    pub fn example(name: String) -> Self {
        let mut params = HashMap::new();
        params.insert("max_amount".to_string(), "1000".to_string());

        Self {
            name,
            version: "1.0.0".to_string(),
            description: Some("Example DSM Content-Addressed Token Policy".to_string()),
            rules: vec![TransferRule {
                name: "Amount limit".to_string(),
                condition: RuleCondition {
                    condition_type: ConditionType::AmountLimit,
                    parameters: params,
                },
                action: RuleAction::Allow,
                priority: 1,
            }],
            metadata: None,
        }
    }
}
