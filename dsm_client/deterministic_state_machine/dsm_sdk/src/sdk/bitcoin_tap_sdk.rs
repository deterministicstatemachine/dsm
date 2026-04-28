//! Bitcoin Tap SDK — Sovereign Bitcoin Settlement via DSM
//!
//! Orchestrates the full lifecycle of vault deposits between Bitcoin and DSM dBTC tokens.
//! Uses hash-locked contracts on both sides: Bitcoin HTLCs and DSM DLVs with
//! matching SHA256 unlock conditions.
//!
//! ## Keg & Tap Model
//!
//! Bitcoin is the global "keg" of collateral. Each DLV with a `BitcoinHTLC`
//! fulfillment mechanism is a "tap" — opening it deposits BTC and mints dBTC;
//! drawing from it finalizes a deposit; planner-driven withdrawals compose the
//! lower-level sweep primitives to route BTC back out.
//!
//! | Tap Phase      | Method                        | Description                    |
//! |----------------|-------------------------------|--------------------------------|
//! | Open Tap       | `open_tap()`                  | BTC → dBTC deposit             |
//! | Draw Tap       | `draw_tap()`                  | Finalize deposit (mint)        |
//! | Plan Withdraw  | `plan_withdrawal()`           | Authoritative dBTC → BTC route |
//! | Pour Partial   | `pour_partial()`              | Fractional sweep leg           |
//! | Close Tap      | `close_tap()`                 | Budget-exhaustion refund       |
//! | Seal Tap       | `seal_tap()`                  | Lock dBTC for atomic deposit   |
//! | Fetch Exec     | `fetch_vault_execution_data()`| Get vault data from storage nodes |
//!
//! ## Trust model
//!
//! Fully trustless (DLV-native):
//! - No custodian, no mint authority
//! - Unlocking a DLV with valid `BitcoinHTLCProof` (preimage + SPV proof) IS the dBTC mint
//! - Locking dBTC in a DLV with `BitcoinHTLC` condition + counterparty claiming = dBTC burn
//! - 1:1 backing enforced by Bitcoin PoW (SPV proof) + SHA256 hash-lock atomicity
//!
//! ## dBTC Token
//!
//! BTC enters DSM as **dBTC** (Deterministic Bitcoin) — a pre-established canonical
//! CPTA policy (same infrastructure as user-created tokens, not native like ERA).
//! dBTC is 1:1 backed by BTC locked in HTLCs. Once minted, dBTC can be transferred
//! bilaterally, exchanged for ERA or any other DSM-built token via normal token operations.
//! All applications using the same frozen dBTC CPTA enter the same economic manifold.
//!
//! No wall clocks — all timeouts are iteration-based. No oracles — verification
//! is storage_node via SPV proofs.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;

use prost::Message;
use rand::{rngs::OsRng, RngCore};

use dsm::{
    bitcoin::{
        script::{build_htlc_script, htlc_p2wsh_address, sha256_hash_lock},
        spv::SpvProof,
        types::BitcoinNetwork,
    },
    crypto::blake3::dsm_domain_hasher,
    commitments::{create_external_commitment, external_evidence_hash, external_source_id},
    types::{
        error::DsmError,
        operations::Operation,
        state_types::State,
        token_types::{TokenMetadata, TokenOperation, TokenSupply, TokenType},
    },
    vault::{DLVManager, FulfillmentMechanism, FulfillmentProof},
};
use dsm::types::proto as generated;

/// dBTC token identifier — canonical across all DSM instances
pub const DBTC_TOKEN_ID: &str = "dBTC";

/// dBTC token symbol
pub const DBTC_SYMBOL: &str = "dBTC";

/// dBTC token name
pub const DBTC_NAME: &str = "Deterministic Bitcoin";

/// dBTC uses 8 decimal places (same as Bitcoin's satoshi precision)
pub const DBTC_DECIMALS: u8 = 8;

/// Maximum dBTC supply in satoshis (21 million BTC)
pub const DBTC_MAX_SUPPLY_SATS: u64 = 21_000_000 * 100_000_000;

/// Canonical minimum confirmation depth for entry and exit anchors.
/// dBTC paper §6.4.1, §6.4.3, Definition 12.3, Remark 12.3:
/// "min_entry_confirmations = min_exit_confirmations = 100 is recommended."
pub const DBTC_MIN_CONFIRMATIONS: u64 = 100;

/// Canonical successor lineage depth bound for dBTC fractional exits.
/// dBTC paper §12.1.1 recommends a small bounded integer (example: 5).
pub const DBTC_MAX_SUCCESSOR_DEPTH: u32 = 5;

/// Canonical minimum vault remainder after fractional exit (satoshis).
/// dBTC paper §12.1.2 worked example uses 100,000 sats.
pub const DBTC_MIN_VAULT_BALANCE_SATS: u64 = 100_000;

/// Maximum settlement poll iterations before the resolver starts warning loudly.
/// Committed withdrawals remain pending until they are explicitly finalized or refunded.
pub const DBTC_MAX_SETTLEMENT_POLLS: u32 = 200;

/// Conservative on-chain dust floor used by SDK guard rails.
/// (P2PKH ~546 sats, P2WSH ~330 sats)
pub const DBTC_DUST_FLOOR_SATS: u64 = 546;

/// Conservative estimate of P2WSH sweep tx fee (vbytes * sat/vbyte).
/// dBTC paper §11.2: exit_amount >= dust_threshold + fee_sweep
/// A P2WSH HTLC claim tx is ~170 vbytes; at 10 sat/vbyte = 1700 sats.
pub const DBTC_ESTIMATED_SWEEP_FEE_SATS: u64 = 2_000;

/// Production floor for the withdrawal fee rate (sat/vbyte). No withdrawal may use a lower rate.
pub const WITHDRAWAL_FEE_RATE_SAT_VB: u64 = 10;

/// Returns the effective withdrawal fee rate in sat/vbyte.
/// Runtime TOML override takes precedence if >= the production floor; otherwise the floor is used.
pub fn withdrawal_fee_rate_sat_vb() -> u64 {
    DbtcParams::resolve().fee_rate_sat_vb
}

pub fn estimated_full_withdrawal_fee_sats() -> u64 {
    crate::sdk::bitcoin_tx_builder::ESTIMATED_CLAIM_VSIZE * withdrawal_fee_rate_sat_vb()
}

pub fn estimated_partial_withdrawal_fee_sats() -> u64 {
    crate::sdk::bitcoin_tx_builder::ESTIMATED_SWEEP_VSIZE * withdrawal_fee_rate_sat_vb()
}

/// Minimum exit amount: must cover dust + sweep fees.
/// dBTC paper §11.2, Invariant 11.2.
pub const DBTC_MIN_EXIT_SATS: u64 = DBTC_DUST_FLOOR_SATS + DBTC_ESTIMATED_SWEEP_FEE_SATS;

/// Runtime-resolved dBTC economic parameters.
///
/// Resolution order: TOML override in `EnvConfig` > compile-time constants above.
/// Cached per-process via `OnceLock` (TOML doesn't hot-reload).
///
/// Operators can tune these per-deployment without recompilation, e.g. raising
/// `estimated_sweep_fee_sats` during high-fee environments.
#[derive(Debug, Clone)]
pub struct DbtcParams {
    pub min_confirmations: u64,
    pub max_successor_depth: u32,
    pub min_vault_balance_sats: u64,
    pub dust_floor_sats: u64,
    pub estimated_sweep_fee_sats: u64,
    pub min_exit_sats: u64,
    /// Effective withdrawal fee rate (sat/vbyte). Always >= WITHDRAWAL_FEE_RATE_SAT_VB.
    pub fee_rate_sat_vb: u64,
}

/// Cached resolved params — loaded once per process.
static DBTC_PARAMS: OnceLock<DbtcParams> = OnceLock::new();

impl DbtcParams {
    /// Resolve parameters: CPTA policy defaults with optional runtime operational overrides.
    ///
    /// Safety defaults are read from the built-in dBTC CPTA policy's
    /// `BitcoinTapConstraint` condition.
    ///
    /// For operational testing/development, selected values can be overridden via
    /// TOML (`EnvConfig`) without recompilation. This affects storage_node runtime
    /// behavior for newly created vaults.
    ///
    /// Result is cached per-process after the first call.
    pub fn resolve() -> &'static DbtcParams {
        DBTC_PARAMS.get_or_init(|| {
            // 1. Load safety params from built-in CPTA policy
            let (policy_bytes, _commit) =
                crate::policy::builtins::bytes_and_commit(crate::policy::builtins::BuiltinPolicy::Dbtc);
            let tap_constraint = dsm::types::policy_types::PolicyFile::from_canonical_bytes(policy_bytes)
                .ok()
                .and_then(|pf| {
                    pf.conditions.into_iter().find_map(|c| {
                        if let dsm::types::policy_types::PolicyCondition::BitcoinTapConstraint {
                            max_successor_depth,
                            min_vault_balance_sats,
                            dust_floor_sats,
                            min_confirmations,
                        } = c
                        {
                            Some((
                                max_successor_depth,
                                min_vault_balance_sats,
                                dust_floor_sats,
                                min_confirmations,
                            ))
                        } else {
                            None
                        }
                    })
                });

            let (max_depth, min_vault, dust, min_conf) = tap_constraint.unwrap_or_else(|| {
                log::warn!(
                    "[DbtcParams::resolve] No BitcoinTapConstraint in dBTC CPTA — using compile-time defaults"
                );
                (
                    DBTC_MAX_SUCCESSOR_DEPTH,
                    DBTC_MIN_VAULT_BALANCE_SATS,
                    DBTC_DUST_FLOOR_SATS,
                    DBTC_MIN_CONFIRMATIONS,
                )
            });

            // 2. Runtime operational overrides from TOML (if provided)
            let cfg_opt = crate::network::NetworkConfigLoader::load_env_config().ok();
            let toml_min_conf = cfg_opt
                .as_ref()
                .and_then(|c| c.dbtc_min_confirmations)
                .filter(|v| *v > 0);
            let min_conf_runtime = match toml_min_conf {
                Some(v) => v, // Explicit TOML override — always honored
                None => {
                    // No explicit override: use network-aware defaults.
                    // Mainnet/testnet keep the full d_min (100) for reorg safety.
                    // Signet (and any non-mainnet/testnet network): 1 confirmation.
                    //
                    // NON_PAPER_MODE: The dBTC paper specifies d_min = 100 for all networks
                    // (Definition 13, §17). The 1-confirmation shortcut is intentional for
                    // development/testing only. It weakens reorg safety and must NOT be used
                    // on mainnet. Gate real mainnet operations behind a TOML override or the
                    // Mainnet/Testnet branch above. See audit finding §5.
                    let network = crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network();
                    match network {
                        dsm::bitcoin::types::BitcoinNetwork::Mainnet
                        | dsm::bitcoin::types::BitcoinNetwork::Testnet => min_conf,
                        _ => {
                            // Signet, regtest, or any test network: 1 confirmation
                            log::info!(
                                "[DbtcParams::resolve] {:?} network detected — using 1 confirmation (not {})",
                                network, min_conf
                            );
                            1
                        }
                    }
                }
            };
            let max_depth_runtime = cfg_opt
                .as_ref()
                .and_then(|c| c.dbtc_max_successor_depth)
                .filter(|v| *v > 0)
                .unwrap_or(max_depth);
            let min_vault_runtime = cfg_opt
                .as_ref()
                .and_then(|c| c.dbtc_min_vault_balance_sats)
                .filter(|v| *v > 0)
                .unwrap_or(min_vault);
            let dust_runtime = cfg_opt
                .as_ref()
                .and_then(|c| c.dbtc_dust_floor_sats)
                .filter(|v| *v > 0)
                .unwrap_or(dust);
            let sweep_fee = cfg_opt
                .as_ref()
                .and_then(|c| c.dbtc_estimated_sweep_fee_sats)
                .unwrap_or(DBTC_ESTIMATED_SWEEP_FEE_SATS);

            log::info!(
                "[DbtcParams::resolve] Policy defaults: min_conf={}, max_depth={}, \
                 min_vault={}, dust={}. Runtime: min_conf={}, max_depth={}, \
                 min_vault={}, dust={}, sweep_fee={}",
                min_conf,
                max_depth,
                min_vault,
                dust,
                min_conf_runtime,
                max_depth_runtime,
                min_vault_runtime,
                dust_runtime,
                sweep_fee
            );

            let fee_rate_runtime = cfg_opt
                .as_ref()
                .and_then(|c| c.dbtc_fee_rate_sat_vb)
                .filter(|v| *v >= WITHDRAWAL_FEE_RATE_SAT_VB)
                .unwrap_or(WITHDRAWAL_FEE_RATE_SAT_VB);

            DbtcParams {
                min_confirmations: min_conf_runtime,
                max_successor_depth: max_depth_runtime,
                min_vault_balance_sats: min_vault_runtime,
                dust_floor_sats: dust_runtime,
                estimated_sweep_fee_sats: sweep_fee,
                min_exit_sats: dust_runtime.saturating_add(sweep_fee),
                fee_rate_sat_vb: fee_rate_runtime,
            }
        })
    }
}

/// External commitment source identifier for Bitcoin tap
const BITCOIN_SOURCE: &str = "bitcoin:mainnet";
const DBTC_VAULT_ADVERTISEMENT_VERSION: u32 = 1;
const DBTC_MANIFOLD_LIST_LIMIT: u32 = 200;

/// Vault operation lifecycle states
#[derive(Debug, Clone, PartialEq)]
pub enum VaultOpState {
    /// Deposit initiated — DLV created, awaiting counterparty Bitcoin HTLC
    Initiated,
    /// Counterparty has created Bitcoin HTLC — awaiting confirmations
    AwaitingConfirmation,
    /// Bitcoin payment confirmed — preimage can be revealed to claim BTC
    Claimable,
    /// Deposit completed — both sides settled, dBTC minted or burned
    Completed,
    /// Deposit expired — refund path available
    Expired,
    /// Refund executed — DLV content reclaimed by creator
    Refunded,
}

/// Direction of the atomic deposit
#[derive(Debug, Clone, PartialEq)]
pub enum VaultDirection {
    /// BTC→dBTC: BTC holder deposits BTC, receives dBTC (DLV unlock = mint)
    BtcToDbtc,
    /// dBTC→BTC: dBTC holder burns dBTC, receives BTC (DLV lock + claim = burn)
    DbtcToBtc,
}

/// Internal vault record tracking the full lifecycle
#[derive(Debug, Clone)]
pub struct VaultOperation {
    pub vault_op_id: String,
    pub direction: VaultDirection,
    pub state: VaultOpState,
    /// SHA256 hash lock binding both sides
    pub hash_lock: [u8; 32],
    /// DSM vault ID
    pub vault_id: Option<String>,
    /// Bitcoin amount in satoshis (= dBTC amount, 1:1)
    pub btc_amount_sats: u64,
    /// Counterparty's Bitcoin compressed pubkey
    pub btc_pubkey: Vec<u8>,
    /// Bitcoin HTLC redeem script (if generated)
    pub htlc_script: Option<Vec<u8>>,
    /// Bitcoin HTLC P2WSH address (if generated)
    pub htlc_address: Option<String>,
    /// External commitment hash for auditability
    pub external_commitment: Option<[u8; 32]>,
    /// Iteration-based refund threshold
    pub refund_iterations: u64,
    /// Creation state number
    pub created_at_state: u64,
    /// Bitcoin block header cached at entry time (80 bytes).
    /// dBTC paper §12.2.3, Invariant 19: set when deposit completes.
    pub entry_header: Option<[u8; 80]>,
    /// Parent vault when this record represents a successor created by
    /// fractional sweep-and-change.
    pub parent_vault_id: Option<String>,
    /// Successor depth in a vault lineage (genesis = 0).
    pub successor_depth: u32,
    /// True when this vault record is a successor created by fractional exit.
    pub is_fractional_successor: bool,
    /// SHA256 hash of the refund preimage h_r (dual-hashlock, path (b)).
    pub refund_hash_lock: [u8; 32],
    /// BTC destination address for dbtc_to_btc withdrawals (bech32).
    pub destination_address: Option<String>,
    /// Funding transaction ID (hex, display byte order) — set after broadcast.
    pub funding_txid: Option<String>,
    /// Bitcoin block header cached at exit time (80 bytes).
    /// dBTC paper §6.4.3: exit anchor stored when sweep/claim tx is buried.
    pub exit_header: Option<[u8; 80]>,
    /// Confirmation depth achieved for the exit anchor (dBTC §12.1.3).
    pub exit_confirm_depth: u32,
    /// Bitcoin txid that funded this vault's HTLC (32 bytes, internal byte order).
    /// Pointer only — withdrawer verifies against Bitcoin directly.
    pub entry_txid: Option<Vec<u8>>,
    /// Random 32-byte nonce per vault — published in advertisements.
    /// η is derived deterministically: BLAKE3("DSM/dbtc-bearer-eta\0" || manifold_seed || deposit_nonce).
    /// Any bearer with manifold_seed can compute η → preimage → sweep.
    pub deposit_nonce: Option<[u8; 32]>,
}

/// Result returned when initiating a deposit
#[derive(Debug, Clone)]
pub struct DepositInitiation {
    pub vault_op_id: String,
    pub hash_lock: [u8; 32],
    pub vault_id: String,
    pub external_commitment: [u8; 32],
    pub htlc_script: Option<Vec<u8>>,
    pub htlc_address: Option<String>,
}

/// Result returned when completing a deposit
#[derive(Debug, Clone)]
pub struct DepositCompletion {
    pub vault_op_id: String,
    pub preimage: Vec<u8>,
    pub vault_id: String,
    /// Unsigned DLV unlock operation produced by the vault manager.
    /// `Some` for withdrawals (dBTC→BTC), `None` for deposits (BTC→dBTC)
    /// where the vault is only activated, not unlocked.
    /// Caller must sign and apply through CoreSDK state machine path when present.
    pub dlv_unlock_operation: Option<Operation>,
    /// The token operation that should be executed to finalize the dBTC state change.
    /// For BTC→dBTC: this is a `Mint` operation (crediting dBTC to the claimer).
    /// For dBTC→BTC: this is a `Burn` operation (destroying the locked dBTC).
    pub token_operation: TokenOperation,
}

/// Result returned when initiating a fractional dBTC exit.
#[derive(Debug, Clone)]
pub struct FractionalExitResult {
    /// Existing vault being partially exited.
    pub source_vault_id: String,
    /// Newly created successor vault holding the remainder.
    pub successor_vault_id: String,
    /// New successor vault op ID.
    pub successor_vault_op_id: String,
    /// Exit vault op ID — the dbtc_to_btc record for the withdrawn amount.
    pub exit_vault_op_id: String,
    /// Satoshis burned for this exit.
    pub exit_amount_sats: u64,
    /// Satoshis remaining in successor vault.
    pub remainder_sats: u64,
    /// Successor depth in lineage.
    pub successor_depth: u32,
    /// HTLC script for successor funding output.
    pub successor_htlc_script: Vec<u8>,
    /// P2WSH address for successor HTLC.
    pub successor_htlc_address: String,
    /// Token operation to execute for the fractional burn.
    pub token_operation: TokenOperation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawalLegKind {
    Full,
    Partial,
}

impl WithdrawalLegKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalPlanLeg {
    pub vault_id: String,
    pub kind: WithdrawalLegKind,
    pub source_amount_sats: u64,
    pub gross_exit_sats: u64,
    pub estimated_fee_sats: u64,
    pub estimated_net_sats: u64,
    pub remainder_sats: u64,
    pub successor_depth_after: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalBlockedVault {
    pub vault_id: String,
    pub amount_sats: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalPlan {
    pub plan_id: String,
    pub plan_class: String,
    pub requested_net_sats: u64,
    pub planned_net_sats: u64,
    pub total_gross_exit_sats: u64,
    pub total_fee_sats: u64,
    pub shortfall_sats: u64,
    pub legs: Vec<WithdrawalPlanLeg>,
    pub blocked_vaults: Vec<WithdrawalBlockedVault>,
    pub policy_commit: [u8; 32],
    pub available_dbtc_sats: u64,
}

/// Result of a full vault data purge (`purge_all_vault_data`).
#[derive(Debug, Clone)]
pub struct PurgeResult {
    /// Number of objects successfully deleted from storage nodes.
    pub remote_deleted: u32,
    /// Number of storage node delete attempts that failed.
    pub remote_failed: u32,
    /// Total SQLite rows deleted across vault/dBTC tables.
    pub local_rows_deleted: u64,
}

/// Execution data fetched from storage node advertisement.
/// Anyone holding dBTC tokens can fetch this — no local vault record needed.
/// Unilateral action: tokens are the key, storage nodes have everything else.
#[derive(Debug, Clone)]
pub struct VaultExecutionData {
    pub vault_id: String,
    pub amount_sats: u64,
    pub successor_depth: u32,
    pub htlc_script: Vec<u8>,
    pub htlc_address: String,
    pub hash_lock: [u8; 32],
    pub deposit_nonce: [u8; 32],
    pub policy_commit: [u8; 32],
    pub vault_content_hash: [u8; 32],
}

#[derive(Debug, Clone)]
struct WithdrawableVault {
    vault_id: String,
    amount_sats: u64,
    successor_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WithdrawalRouteCandidate {
    legs: Vec<WithdrawalPlanLeg>,
    planned_net_sats: u64,
    total_gross_exit_sats: u64,
    total_fee_sats: u64,
}

#[derive(Debug, Clone)]
struct StorageNodeVaultRoutingInventory {
    records_by_vault: HashMap<String, Vec<crate::storage::client_db::PersistedVaultRecord>>,
    records_by_parent: HashMap<String, Vec<crate::storage::client_db::PersistedVaultRecord>>,
    storage_node_vault_ids: HashSet<String>,
}

#[derive(Debug, Clone)]
struct StorageNodeVaultRoutingView {
    vault_id: String,
    amount_sats: u64,
    successor_depth: u32,
    lifecycle_state: String,
    routeable: bool,
    busy_reason: Option<String>,
    updated_state_number: u64,
    vault_proto_bytes: Vec<u8>,
    /// Bitcoin txid that funded this vault's HTLC (32 bytes, internal byte order).
    entry_txid: Option<Vec<u8>>,
    /// HTLC P2WSH address — included in advertisement per spec §8 Definition 7.
    htlc_address: Option<String>,
    /// BLAKE3("DSM/script-commit" || htlc_script) — commits the spending template (spec Def 9).
    script_commit: Option<Vec<u8>>,
    /// Serialized DbtcRedeemParams — public construction data for the HTLC spend (spec Def 9/11).
    redeem_params: Option<Vec<u8>>,
    /// Random 32-byte deposit nonce — published in vault advertisements for bearer η derivation.
    deposit_nonce: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct PublishedVaultAdvertisement {
    key: String,
    advertisement: generated::DbtcVaultAdvertisementV1,
}

#[derive(Debug, Clone)]
struct WithdrawalSelectorInput {
    eligible: Vec<WithdrawableVault>,
    blocked: Vec<WithdrawalBlockedVault>,
    eligible_advertisements: Vec<generated::DbtcVaultAdvertisementV1>,
}

// In-process mock storage backend.  Active under `#[cfg(test)]` for
// crate-internal tests AND under `--features demos` so example
// binaries (notably `cargo run --example detfi_demo`) can drive the
// full pipeline without standing up real storage nodes.  The `demos`
// feature is opt-in (not in the default set) so production builds
// never see this path.
#[cfg(any(test, feature = "demos"))]
#[derive(Default)]
struct DbtcStorageTestState {
    list_results: std::collections::VecDeque<Result<generated::ObjectListResponseV1, String>>,
    put_failures: HashMap<String, String>,
    get_failures: HashMap<String, String>,
    object_store: HashMap<String, Vec<u8>>,
}

#[cfg(any(test, feature = "demos"))]
static DBTC_STORAGE_TEST_STATE: once_cell::sync::Lazy<std::sync::Mutex<DbtcStorageTestState>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(DbtcStorageTestState::default()));

#[cfg(any(test, feature = "demos"))]
fn dbtc_storage_test_state() -> std::sync::MutexGuard<'static, DbtcStorageTestState> {
    match DBTC_STORAGE_TEST_STATE.lock() {
        Ok(state) => state,
        Err(poisoned) => {
            log::warn!("dbtc storage test state mutex poisoned; recovering inner state");
            poisoned.into_inner()
        }
    }
}

/// Bitcoin Tap SDK — the "taproom" that manages all taps on the Bitcoin keg.
///
/// Orchestrates bidirectional vault deposits between Bitcoin and DSM dBTC tokens.
/// Each deposit phase publishes an external commitment for cross-chain auditability.
///
/// ## Usage
///
/// ```ignore
/// let tap = BitcoinTapSdk::new(dlv_manager);
///
/// // Register dBTC token at initialization
/// let dbtc_metadata = tap.dbtc_token_metadata([0u8; 32]);
/// // ... register metadata with your token system ...
///
/// // Open Tap: Alice deposits BTC, gets dBTC
/// let initiation = tap.open_tap(...).await?;
/// // ... Alice funds the Bitcoin HTLC ...
/// let completion = tap.draw_tap(...).await?;
/// // Execute completion.token_operation (Mint) via TokenSDK
///
/// // Review a withdrawal route from active vaults
/// let plan = tap.plan_withdrawal(250_000, "bc1q...").await?;
/// // Execute the returned plan through the invoke handler / executor
/// ```
pub struct BitcoinTapSdk {
    dlv_manager: Arc<DLVManager>,
    pending_ops: Arc<RwLock<HashMap<String, VaultOperation>>>,
}

impl BitcoinTapSdk {
    /// Read the device's canonical dBTC balance from the cached
    /// `bcr_device_heads` row (§9 fungibility — keyed by 32B CPTA
    /// `policy_commit`, no string-key projection, no scan over historical
    /// states).
    fn canonical_archived_dbtc_balance(device_id: &[u8; 32]) -> Option<u64> {
        let head = crate::storage::client_db::load_bcr_device_head(device_id).ok()??;
        Some(head.balance(crate::policy::builtins::DBTC_POLICY_COMMIT))
    }

    pub fn new(dlv_manager: Arc<DLVManager>) -> Self {
        Self {
            dlv_manager,
            pending_ops: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Public accessor for the DLV manager (used by vault monitor routes).
    pub fn dlv_manager(&self) -> &Arc<DLVManager> {
        &self.dlv_manager
    }

    /// Public accessor for pending ops map (used by fund_and_broadcast route).
    pub fn pending_ops(&self) -> &RwLock<HashMap<String, VaultOperation>> {
        &self.pending_ops
    }

    // -----------------------------------------------------------------------
    // Persistence (Invariant 18, §12.2.2)
    // -----------------------------------------------------------------------

    /// Restore vault records and vault cache from SQLite.
    ///
    /// Call this after constructing a new `BitcoinTapSdk` to rehydrate
    /// in-memory state from persistent storage. Ensures the SDK can
    /// autonomously complete or refund deposits after a restart.
    pub async fn restore_from_persistence(&self) -> Result<(usize, usize), DsmError> {
        use crate::storage::client_db;

        // 1. Restore vault records
        let persisted_records = client_db::list_vault_records_db().map_err(|e| {
            DsmError::invalid_operation(format!("Failed to list vault records: {e}"))
        })?;
        let record_count = persisted_records.len();
        {
            let mut ops = self.pending_ops.write().await;
            for p in persisted_records {
                let record = Self::persisted_to_vault_op(p);
                ops.insert(record.vault_op_id.clone(), record);
            }
        }

        // 2. Restore vault store (all states — active, limbo, unlocked, etc.)
        let vault_ids = client_db::list_all_vault_ids()
            .map_err(|e| DsmError::invalid_operation(format!("Failed to list vault store: {e}")))?;
        let vault_count = vault_ids.len();
        for vid in &vault_ids {
            if let Ok(Some((proto_bytes, _state, entry_hdr, _sats))) = client_db::get_vault(vid) {
                let proto = dsm::types::proto::LimboVaultProto::decode(proto_bytes.as_ref())
                    .map_err(|e| {
                        DsmError::serialization_error(
                            "LimboVaultProto",
                            "decode",
                            None::<&str>,
                            Some(e),
                        )
                    })?;
                let mut vault = dsm::vault::LimboVault::try_from(proto)?;

                // Restore entry header from persistence (always 80 bytes in vault_store)
                vault.entry_header = Some(entry_hdr);

                // DLVManager::add_vault() handles dedup (overwrites if exists)
                self.dlv_manager.add_vault(vault).await?;
            }
        }

        log::info!(
            "dBTC persistence restored: {} deposits, {} vaults",
            record_count,
            vault_count
        );
        Ok((record_count, vault_count))
    }

    /// Persist a vault record to SQLite (write-through).
    fn persist_vault_op(record: &VaultOperation) -> Result<(), DsmError> {
        use crate::storage::client_db;
        let persisted = Self::to_persisted_vault_record(record);
        client_db::upsert_vault_record(&persisted).map_err(|e| DsmError::Storage {
            context: format!(
                "Failed to persist vault record {}: {}",
                record.vault_op_id, e
            ),
            source: None,
        })
    }

    /// Persist a vault to SQLite (write-through).
    /// Extracts all data under the vault lock, drops it, THEN writes to SQLite
    /// to avoid holding the async Mutex across a blocking SQLite call.
    async fn persist_vault(&self, vault_id: &str) -> Result<(), DsmError> {
        use crate::storage::client_db;
        use dsm::vault::fulfillment::FulfillmentMechanism;
        let vid32 = crate::util::text_id::decode_bytes32(vault_id).ok_or_else(|| {
            DsmError::invalid_operation(format!(
                "persist_vault: vault_id {vault_id} is not a valid Base32 32-byte id"
            ))
        })?;
        let (proto_bytes, state_str, entry_hdr, btc_amount_sats) = {
            let vault_lock =
                self.dlv_manager
                    .get_vault(&vid32)
                    .await
                    .map_err(|e| DsmError::Storage {
                        context: format!("Failed to get vault {} for persistence: {}", vault_id, e),
                        source: None,
                    })?;
            let vault = vault_lock.lock().await;
            let proto: dsm::types::proto::LimboVaultProto = (&*vault).into();
            let proto_bytes = proto.encode_to_vec();
            let state_str = match &vault.state {
                dsm::vault::VaultState::Limbo => "limbo",
                dsm::vault::VaultState::Active => "active",
                dsm::vault::VaultState::Unlocked { .. } => "unlocked",
                dsm::vault::VaultState::Claimed { .. } => "claimed",
                dsm::vault::VaultState::Invalidated { .. } => "invalidated",
            };
            let btc_amount_sats = match &vault.fulfillment_condition {
                FulfillmentMechanism::BitcoinHTLC {
                    expected_btc_amount_sats,
                    ..
                } => *expected_btc_amount_sats,
                _ => 0,
            };
            let entry_hdr = vault.entry_header.unwrap_or([0u8; 80]);
            (proto_bytes, state_str, entry_hdr, btc_amount_sats)
        };
        client_db::put_vault(
            vault_id,
            &proto_bytes,
            state_str,
            &entry_hdr,
            btc_amount_sats,
        )
        .map_err(|e| DsmError::Storage {
            context: format!("Failed to persist vault {}: {}", vault_id, e),
            source: None,
        })?;

        self.publish_vault_advertisement_mandatory(vault_id).await?;
        Ok(())
    }

    /// Persist vault data to storage_node SQLite only — does NOT publish to storage nodes.
    ///
    /// Used for successor vaults created by `pour_partial`: per spec §7 Remark 2,
    /// the successor advertisement must be published only AFTER the sweep tx reaches
    /// dmin confirmations (entry_txid = txid(txsweep)), not at creation time.
    async fn persist_vault_storage_node_only(&self, vault_id: &str) -> Result<(), DsmError> {
        use crate::storage::client_db;
        use dsm::vault::fulfillment::FulfillmentMechanism;
        let vid32 = crate::util::text_id::decode_bytes32(vault_id)
            .ok_or_else(|| DsmError::invalid_operation(format!(
                "persist_vault_storage_node_only: vault_id {vault_id} is not a valid Base32 32-byte id"
            )))?;
        let (proto_bytes, state_str, entry_hdr, btc_amount_sats) = {
            let vault_lock =
                self.dlv_manager
                    .get_vault(&vid32)
                    .await
                    .map_err(|e| DsmError::Storage {
                        context: format!(
                            "Failed to get vault {} for storage_node persistence: {}",
                            vault_id, e
                        ),
                        source: None,
                    })?;
            let vault = vault_lock.lock().await;
            let proto: dsm::types::proto::LimboVaultProto = (&*vault).into();
            let proto_bytes = proto.encode_to_vec();
            let state_str = match &vault.state {
                dsm::vault::VaultState::Limbo => "limbo",
                dsm::vault::VaultState::Active => "active",
                dsm::vault::VaultState::Unlocked { .. } => "unlocked",
                dsm::vault::VaultState::Claimed { .. } => "claimed",
                dsm::vault::VaultState::Invalidated { .. } => "invalidated",
            };
            let btc_amount_sats = match &vault.fulfillment_condition {
                FulfillmentMechanism::BitcoinHTLC {
                    expected_btc_amount_sats,
                    ..
                } => *expected_btc_amount_sats,
                _ => 0,
            };
            let entry_hdr = vault.entry_header.unwrap_or([0u8; 80]);
            (proto_bytes, state_str, entry_hdr, btc_amount_sats)
        };
        client_db::put_vault(
            vault_id,
            &proto_bytes,
            state_str,
            &entry_hdr,
            btc_amount_sats,
        )
        .map_err(|e| DsmError::Storage {
            context: format!("Failed to persist vault storage_nodely {}: {}", vault_id, e),
            source: None,
        })?;
        Ok(())
    }

    /// Publish a vault advertisement to storage nodes. Hard error if publication
    /// fails — per dBTC spec §3.1 Step 4, storage nodes must mirror the creation
    /// artifact at vault creation time. The vault is not usable until published.
    pub(crate) async fn publish_vault_advertisement_mandatory(
        &self,
        vault_id: &str,
    ) -> Result<(), DsmError> {
        // Integration tests set DSM_SDK_TEST_MODE=1 but compile the library
        // without #[cfg(test)], so storage_put_bytes hits real storage nodes.
        // Skip network publication in test mode — the vault is still persisted
        // storage_nodely and the test can verify storage_node state.
        if std::env::var("DSM_SDK_TEST_MODE").is_ok_and(|v| v == "1") {
            log::info!(
                "[bitcoin_tap] Skipping mandatory vault publication in test mode for {vault_id}"
            );
            return Ok(());
        }

        let device_id_bytes =
            crate::sdk::app_state::AppState::get_device_id().ok_or_else(|| {
                DsmError::invalid_operation(
                    "vault publication requires device_id (bootstrap not complete)",
                )
            })?;
        if device_id_bytes.len() != 32 {
            return Err(DsmError::invalid_operation(format!(
                "vault publication requires 32-byte device_id, got {}",
                device_id_bytes.len()
            )));
        }
        let mut controller_device_id = [0u8; 32];
        controller_device_id.copy_from_slice(&device_id_bytes);
        self.publish_vault_advertisement(vault_id, &controller_device_id)
            .await
            .map_err(|e| {
                DsmError::storage(
                    format!(
                        "mandatory vault publication to storage nodes failed for {vault_id}: {e}"
                    ),
                    None::<std::io::Error>,
                )
            })
    }

    // Withdrawal State Machine (dBTC paper §13: Commit → Settle | Refund)
    // -----------------------------------------------------------------------

    /// Commit dBTC into an in-flight withdrawal state.
    ///
    /// Convert domain VaultOperation to persistence DTO.
    pub fn to_persisted_vault_record(
        r: &VaultOperation,
    ) -> crate::storage::client_db::PersistedVaultRecord {
        crate::storage::client_db::PersistedVaultRecord {
            vault_op_id: r.vault_op_id.clone(),
            direction: match r.direction {
                VaultDirection::BtcToDbtc => "btc_to_dbtc".to_string(),
                VaultDirection::DbtcToBtc => "dbtc_to_btc".to_string(),
            },
            vault_state: match r.state {
                VaultOpState::Initiated => "initiated".to_string(),
                VaultOpState::AwaitingConfirmation => "awaiting_confirmation".to_string(),
                VaultOpState::Claimable => "claimable".to_string(),
                VaultOpState::Completed => "completed".to_string(),
                VaultOpState::Expired => "expired".to_string(),
                VaultOpState::Refunded => "refunded".to_string(),
            },
            hash_lock: r.hash_lock.to_vec(),
            vault_id: r.vault_id.clone(),
            btc_amount_sats: r.btc_amount_sats,
            btc_pubkey: r.btc_pubkey.clone(),
            htlc_script: r.htlc_script.clone(),
            htlc_address: r.htlc_address.clone(),
            external_commitment: r.external_commitment.map(|c| c.to_vec()),
            refund_iterations: r.refund_iterations,
            created_at_state: r.created_at_state,
            entry_header: r.entry_header.map(|eh| eh.to_vec()),
            parent_vault_id: r.parent_vault_id.clone(),
            successor_depth: r.successor_depth,
            is_fractional_successor: r.is_fractional_successor,
            refund_hash_lock: r.refund_hash_lock.to_vec(),
            destination_address: r.destination_address.clone(),
            funding_txid: r.funding_txid.clone(),
            exit_amount_sats: 0,
            exit_header: r.exit_header.map(|eh| eh.to_vec()),
            exit_confirm_depth: r.exit_confirm_depth,
            entry_txid: r.entry_txid.clone(),
            deposit_nonce: r.deposit_nonce.map(|n| n.to_vec()),
        }
    }

    /// Convert persistence DTO to domain VaultOperation.
    fn persisted_to_vault_op(p: crate::storage::client_db::PersistedVaultRecord) -> VaultOperation {
        let direction = match p.direction.as_str() {
            "dbtc_to_btc" => VaultDirection::DbtcToBtc,
            _ => VaultDirection::BtcToDbtc,
        };
        let state = match p.vault_state.as_str() {
            "awaiting_confirmation" => VaultOpState::AwaitingConfirmation,
            "claimable" => VaultOpState::Claimable,
            "completed" => VaultOpState::Completed,
            "expired" => VaultOpState::Expired,
            "refunded" => VaultOpState::Refunded,
            _ => VaultOpState::Initiated,
        };
        let mut hash_lock = [0u8; 32];
        if p.hash_lock.len() == 32 {
            hash_lock.copy_from_slice(&p.hash_lock);
        }
        let external_commitment = p.external_commitment.and_then(|c| {
            if c.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&c);
                Some(arr)
            } else {
                None
            }
        });
        let entry_header = p.entry_header.and_then(|eh| {
            if eh.len() == 80 {
                let mut arr = [0u8; 80];
                arr.copy_from_slice(&eh);
                Some(arr)
            } else {
                None
            }
        });
        VaultOperation {
            vault_op_id: p.vault_op_id,
            direction,
            state,
            hash_lock,
            vault_id: p.vault_id,
            btc_amount_sats: p.btc_amount_sats,
            btc_pubkey: p.btc_pubkey,
            htlc_script: p.htlc_script,
            htlc_address: p.htlc_address,
            external_commitment,
            refund_iterations: p.refund_iterations,
            created_at_state: p.created_at_state,
            entry_header,
            parent_vault_id: p.parent_vault_id,
            successor_depth: p.successor_depth,
            is_fractional_successor: p.is_fractional_successor,
            refund_hash_lock: {
                let mut h = [0u8; 32];
                if p.refund_hash_lock.len() >= 32 {
                    h.copy_from_slice(&p.refund_hash_lock[..32]);
                }
                h
            },
            destination_address: p.destination_address,
            funding_txid: p.funding_txid,
            exit_header: p.exit_header.and_then(|eh| {
                if eh.len() == 80 {
                    let mut arr = [0u8; 80];
                    arr.copy_from_slice(&eh);
                    Some(arr)
                } else {
                    None
                }
            }),
            exit_confirm_depth: p.exit_confirm_depth,
            entry_txid: p.entry_txid,
            deposit_nonce: p.deposit_nonce.and_then(|n| {
                if n.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&n);
                    Some(arr)
                } else {
                    None
                }
            }),
        }
    }

    async fn cache_vault_op(&self, record: VaultOperation) -> VaultOperation {
        let mut ops = self.pending_ops.write().await;
        ops.insert(record.vault_op_id.clone(), record.clone());
        record
    }

    /// Load a single vault from SQLite into the in-memory DLV manager if not already present.
    ///
    /// This handles the case where a vault was received mid-session (e.g., via BLE bilateral
    /// transfer) and persisted to SQLite, but the DLV manager's in-memory map hasn't been
    /// updated yet. Called on-demand before vault access paths (like draw_tap).
    ///
    /// For vaults loaded from storage nodes, the stored LimboVaultProto may be a
    /// minimal stub without `encrypted_content`, `content_commitment`,
    /// or `reference_state_hash`. These vaults cannot be deserialized via the full
    /// `LimboVault::try_from()` path. Instead, we construct a minimal `LimboVault` directly
    /// from the proto fields — this is safe because dBTC BitcoinHTLC vaults only need the
    /// fulfillment condition (hash_lock, btc_pubkey, etc.) for exit operations.
    async fn ensure_vault_in_memory(&self, vault_id: &str) -> Result<(), DsmError> {
        let vid32 = crate::util::text_id::decode_bytes32(vault_id).ok_or_else(|| {
            DsmError::invalid_operation(format!(
                "ensure_vault_in_memory: vault_id {vault_id} is not a valid Base32 32-byte id"
            ))
        })?;
        // Check if already in DLV manager
        if self.dlv_manager.get_vault(&vid32).await.is_ok() {
            return Ok(());
        }

        // Not in memory — try to load from SQLite
        if let Ok(Some((proto_bytes, db_state, entry_hdr, _sats))) =
            crate::storage::client_db::get_vault(vault_id)
        {
            let proto =
                dsm::types::proto::LimboVaultProto::decode(proto_bytes.as_ref()).map_err(|e| {
                    DsmError::serialization_error(
                        "LimboVaultProto",
                        "decode",
                        None::<&str>,
                        Some(e),
                    )
                })?;

            // Try the full deserialization path first. If it fails (e.g., missing
            // encrypted_content for v2 hint-originated vaults), fall back to
            // constructing a minimal LimboVault from the proto fields.
            let vault = match dsm::vault::LimboVault::try_from(proto.clone()) {
                Ok(mut v) => {
                    v.entry_header = Some(entry_hdr);
                    v
                }
                Err(_) => {
                    // v2 hint vault — construct minimal LimboVault directly.
                    // Only the fulfillment condition is needed for exit operations.
                    let fc_proto = proto.fulfillment_condition.ok_or_else(|| {
                        DsmError::invalid_operation(
                            "vault proto has no fulfillment_condition — cannot load",
                        )
                    })?;
                    let fulfillment_condition =
                        dsm::vault::FulfillmentMechanism::try_from(fc_proto).map_err(|e| {
                            DsmError::serialization_error(
                                "FulfillmentMechanism",
                                "try_from",
                                None::<&str>,
                                Some(e),
                            )
                        })?;

                    let mut ref_hash = [0u8; 32];
                    if proto.reference_state_hash.len() == 32 {
                        ref_hash.copy_from_slice(&proto.reference_state_hash);
                    }

                    if proto.id.len() != 32 {
                        return Err(DsmError::serialization_error(
                            "LimboVaultProto.id",
                            "length",
                            None::<&str>,
                            None::<core::convert::Infallible>,
                        ));
                    }
                    let mut pid = [0u8; 32];
                    pid.copy_from_slice(&proto.id);
                    let mut v =
                        dsm::vault::LimboVault::new_minimal(pid, fulfillment_condition, ref_hash);
                    v.entry_header = Some(entry_hdr);
                    log::info!(
                        "[bitcoin_tap] Using minimal vault construction for hint-originated vault {vault_id}"
                    );
                    v
                }
            };

            // Apply persisted vault state to the in-memory vault cache.
            let mut vault = vault;
            if db_state == "active" {
                vault.state = dsm::vault::VaultState::Active;
            }

            self.dlv_manager.add_vault(vault).await?;
            log::info!(
                "[bitcoin_tap] Loaded vault {vault_id} from SQLite into DLV manager (mid-session, state={db_state})"
            );
        }
        Ok(())
    }

    /// Load a remote vault (discovered on storage nodes) into the in-memory DLV manager.
    ///
    /// Downloads the vault protobuf from storage nodes via `vault_proto_key`, verifies
    /// the digest matches, decodes the `LimboVaultProto`, constructs a `LimboVault`,
    /// and registers it with the DLV manager so withdrawal execution can proceed.
    ///
    /// Per dBTC §6.2: at withdrawal, the device synchronizes the manifold from storage
    /// nodes, verifies storage_nodely, then computes the eligible set.
    async fn load_remote_vault_into_memory(
        &self,
        advertisement: &generated::DbtcVaultAdvertisementV1,
    ) -> Result<(), DsmError> {
        let vault_id = &advertisement.vault_id;
        let vid32 = crate::util::text_id::decode_bytes32(vault_id).ok_or_else(|| {
            DsmError::invalid_operation(format!(
                "load_remote_vault_into_memory: vault_id {vault_id} is not a valid Base32 32-byte id"
            ))
        })?;

        // Already loaded?
        if self.dlv_manager.get_vault(&vid32).await.is_ok() {
            return Ok(());
        }

        // Download vault proto from storage nodes
        if advertisement.vault_proto_key.trim().is_empty() {
            return Err(DsmError::invalid_operation(
                "remote vault has no vault_proto_key",
            ));
        }
        let payload = Self::storage_get_bytes(&advertisement.vault_proto_key).await?;

        // Verify digest — mandatory for remote vault loading (security-sensitive path)
        if advertisement.vault_proto_digest.len() != 32 {
            return Err(DsmError::invalid_operation(
                "remote vault advertisement missing valid 32-byte digest",
            ));
        }
        let digest = dsm::crypto::blake3::domain_hash("DSM/vault-ad", &payload);
        if digest.as_bytes() != advertisement.vault_proto_digest.as_slice() {
            return Err(DsmError::invalid_operation(
                "remote vault proto digest mismatch after download",
            ));
        }

        // Decode
        let proto = generated::LimboVaultProto::decode(payload.as_slice()).map_err(|e| {
            DsmError::serialization_error(
                "LimboVaultProto",
                "decode",
                Some(advertisement.vault_proto_key.clone()),
                Some(e),
            )
        })?;

        // Construct LimboVault — same logic as ensure_vault_in_memory fallback path
        let vault = match dsm::vault::LimboVault::try_from(proto.clone()) {
            Ok(v) => v,
            Err(_) => {
                let fc_proto = proto.fulfillment_condition.ok_or_else(|| {
                    DsmError::invalid_operation("remote vault proto has no fulfillment_condition")
                })?;
                let fulfillment_condition = dsm::vault::FulfillmentMechanism::try_from(fc_proto)
                    .map_err(|e| {
                        DsmError::serialization_error(
                            "FulfillmentMechanism",
                            "try_from",
                            None::<&str>,
                            Some(e),
                        )
                    })?;

                let mut ref_hash = [0u8; 32];
                if proto.reference_state_hash.len() == 32 {
                    ref_hash.copy_from_slice(&proto.reference_state_hash);
                }

                if proto.id.len() != 32 {
                    return Err(DsmError::serialization_error(
                        "LimboVaultProto.id",
                        "length",
                        None::<&str>,
                        None::<core::convert::Infallible>,
                    ));
                }
                let mut pid = [0u8; 32];
                pid.copy_from_slice(&proto.id);
                let mut v =
                    dsm::vault::LimboVault::new_minimal(pid, fulfillment_condition, ref_hash);
                v.state = dsm::vault::VaultState::Active;
                log::info!(
                    "[bitcoin_tap] Using minimal vault construction for remote vault {vault_id}"
                );
                v
            }
        };

        // No local caching — the receiver has no business storing vault data
        // locally. Storage nodes are the source of truth. The tokens are the key.
        // Data is fetched on-the-fly into memory for computation, then discarded.
        self.dlv_manager.add_vault(vault).await?;
        log::info!(
            "[bitcoin_tap] Loaded remote vault {vault_id} from storage nodes into DLV manager"
        );

        Ok(())
    }

    async fn load_vault_op_by_id_from_store(
        &self,
        vault_op_id: &str,
    ) -> Result<Option<VaultOperation>, DsmError> {
        let persisted =
            crate::storage::client_db::get_vault_record_by_id(vault_op_id).map_err(|e| {
                DsmError::storage(
                    format!("load vault record by id {vault_op_id}: {e}"),
                    None::<std::io::Error>,
                )
            })?;
        match persisted {
            Some(p) => Ok(Some(
                self.cache_vault_op(Self::persisted_to_vault_op(p)).await,
            )),
            None => Ok(None),
        }
    }

    async fn load_vault_op_by_vault_from_store(
        &self,
        vault_id: &str,
    ) -> Result<Option<VaultOperation>, DsmError> {
        let persisted =
            crate::storage::client_db::get_vault_record_by_vault_id(vault_id).map_err(|e| {
                DsmError::storage(
                    format!("load vault record by vault {vault_id}: {e}"),
                    None::<std::io::Error>,
                )
            })?;
        match persisted {
            Some(p) => Ok(Some(
                self.cache_vault_op(Self::persisted_to_vault_op(p)).await,
            )),
            None => Ok(None),
        }
    }

    /// Get the canonical dBTC token ID.
    pub fn dbtc_token_id() -> &'static str {
        DBTC_TOKEN_ID
    }

    /// Create dBTC token metadata for registration with the token system.
    ///
    /// dBTC is a pre-established canonical CPTA policy with:
    /// - `token_id: "dBTC"`, `symbol: "dBTC"`, `decimals: 8`
    /// - `token_type: TokenType::Wrapped`
    /// - No mint authority — the DLV mechanism IS the authorization
    ///
    /// # Parameters
    /// - `tap_identity`: The identity registering the dBTC token (32-byte device ID)
    pub fn dbtc_token_metadata(tap_identity: [u8; 32]) -> TokenMetadata {
        let mut fields = HashMap::new();
        fields.insert("asset_class".to_string(), "wrapped".to_string());
        fields.insert("backing_asset".to_string(), "bitcoin".to_string());
        fields.insert("backing_chain".to_string(), "bitcoin:mainnet".to_string());
        fields.insert("backing_ratio".to_string(), "1:1".to_string());
        fields.insert(
            "max_supply_sats".to_string(),
            DBTC_MAX_SUPPLY_SATS.to_string(),
        );
        fields.insert("mint_mechanism".to_string(), "dlv_native".to_string());
        fields.insert(
            "policy_commit".to_string(),
            crate::util::text_id::encode_base32_crockford(
                crate::policy::builtins::DBTC_POLICY_COMMIT,
            ),
        );

        let mut meta = TokenMetadata::new(
            DBTC_TOKEN_ID,
            DBTC_NAME,
            DBTC_SYMBOL,
            DBTC_DECIMALS,
            TokenType::Wrapped,
            tap_identity,
            0,
            Some(format!(
                "dsm:policy:{}",
                crate::util::text_id::encode_base32_crockford(
                    crate::policy::builtins::DBTC_POLICY_COMMIT
                )
            )),
        );
        meta.description = Some(
            "Deterministic Bitcoin on DSM. 1:1 backed by BTC locked in HTLCs. \
             Minted via DLV unlock with SPV proof; burned via DLV lock + counterparty claim."
                .to_string(),
        );
        meta.fields = fields;
        meta.policy_anchor = Some(format!(
            "dsm:policy:{}",
            crate::util::text_id::encode_base32_crockford(
                crate::policy::builtins::DBTC_POLICY_COMMIT
            )
        ));
        meta
    }

    /// Create the `TokenOperation::Create` for dBTC registration.
    ///
    /// Returns the operation that should be executed via the token system to
    /// register dBTC as a new token. Supply starts at 0 (minted on demand).
    pub fn dbtc_create_operation(tap_identity: [u8; 32]) -> TokenOperation {
        let metadata = Self::dbtc_token_metadata(tap_identity);
        TokenOperation::Create {
            metadata: Box::new(metadata),
            supply: TokenSupply::Fixed(DBTC_MAX_SUPPLY_SATS),
            fee: 0, // Canonical token registration is fee-exempt
        }
    }

    // -----------------------------------------------------------------------
    // BTC → dBTC flow (deposit BTC, mint dBTC)
    // -----------------------------------------------------------------------

    /// Initiate a BTC→dBTC atomic deposit.
    ///
    /// Creates a DLV locked with `BitcoinHTLC { hash_lock }`. When the DLV is
    /// unlocked with a valid `BitcoinHTLCProof` (preimage + SPV proof of BTC
    /// deposit), the claimer receives dBTC equal to `btc_amount_sats`.
    ///
    /// **DLV unlock = dBTC mint.** No separate mint authority.
    ///
    /// # Parameters
    /// - `btc_amount_sats`: Amount of BTC being deposited (in satoshis). This
    ///   becomes the dBTC mint amount (1:1 ratio).
    /// - `btc_pubkey`: Depositor's compressed Bitcoin public key (33 bytes)
    /// - `refund_iterations`: State iterations before creator can reclaim
    /// - `reference_state`: Current DSM state for anchoring
    /// - `network`: Bitcoin network for header chain verification
    ///
    /// # Parameters
    /// - `btc_amount_sats`: Amount of BTC in satoshis (= dBTC to mint, 1:1)
    /// - `btc_pubkey`: Bitcoin compressed public key (33 bytes)
    /// - `refund_iterations`: DSM iterations before creator can reclaim the DLV
    /// - `kem_public_key`: Kyber public key (1184 bytes) for DLV content encryption
    ///   and intended-recipient access control.
    /// - `reference_state`: Current DSM state
    /// - `network`: Bitcoin network (mainnet/testnet/signet)
    #[allow(clippy::too_many_arguments)]
    pub async fn open_tap(
        &self,
        btc_amount_sats: u64,
        btc_pubkey: &[u8],
        refund_iterations: u64,
        reference_state: &State,
        network: BitcoinNetwork,
        kem_public_key: &[u8],
    ) -> Result<DepositInitiation, DsmError> {
        let params = DbtcParams::resolve();
        if btc_pubkey.len() != 33 {
            return Err(DsmError::invalid_operation(
                "Bitcoin pubkey must be 33 bytes (compressed)",
            ));
        }
        if btc_amount_sats == 0 {
            return Err(DsmError::invalid_operation(
                "BTC amount must be greater than 0",
            ));
        }
        // Bearer-derived η: deposit_nonce is random per vault, manifold_seed is secret per CPTA.
        // η = BLAKE3("DSM/dbtc-bearer-eta\0" || manifold_seed || deposit_nonce)
        // Any bearer with manifold_seed + deposit_nonce can derive η → preimage → sweep.
        let policy_commit = Self::dbtc_policy_commit();
        let manifold_seed = crate::storage::client_db::get_or_create_manifold_seed(&policy_commit)
            .map_err(|e| {
                DsmError::storage(format!("manifold_seed: {e}"), None::<std::io::Error>)
            })?;
        let mut deposit_nonce = [0u8; 32];
        let mut os_rng = OsRng;
        os_rng.fill_bytes(&mut deposit_nonce);
        let eta = Self::derive_bearer_eta(&manifold_seed, &deposit_nonce);
        let preimage = Self::derive_preimage_from_eta(&eta);
        let hash_lock = sha256_hash_lock(&preimage);

        // Math-owned vault: derive claim pubkey from preimage.
        // Any bearer who holds manifold_seed can re-derive the private key at sweep time.
        let (_, claim_pubkey) =
            crate::sdk::bitcoin_tx_builder::derive_claim_keypair(&preimage, &hash_lock)?;

        // Derive refund hash lock: h_r = SHA256(rk_V)
        let fulfillment_bytes = hash_lock.to_vec();
        let refund_key = dsm::crypto::blake3::domain_hash_bytes(
            "DSM/dlv-refund",
            &[&fulfillment_bytes[..], &refund_iterations.to_le_bytes()].concat(),
        );
        let refund_hash_lock = sha256_hash_lock(&refund_key);

        let htlc_script =
            build_htlc_script(&hash_lock, &refund_hash_lock, &claim_pubkey, btc_pubkey)?;
        let htlc_address = htlc_p2wsh_address(&htlc_script, network)?;

        // Signet/Testnet: 1 confirmation is enough (no PoW checkpoints, fast blocks).
        // Mainnet: full params.min_confirmations (100-block burial per dBTC §6.4).
        //
        // NON_PAPER_MODE: The paper requires d_min = 100 on all networks (§17).
        // The 1-confirmation shortcut is intentional for development and testing
        // only; it must not be deployed to mainnet vaults. See audit finding §5.
        let effective_min_confirmations = match network {
            BitcoinNetwork::Signet | BitcoinNetwork::Testnet => 1,
            _ => params.min_confirmations,
        };

        // Create DLV with BitcoinHTLC fulfillment condition
        let condition = FulfillmentMechanism::BitcoinHTLC {
            hash_lock,
            refund_hash_lock,
            refund_iterations,
            bitcoin_pubkey: claim_pubkey.to_vec(),
            expected_btc_amount_sats: btc_amount_sats,
            network: network.to_u32(),
            min_confirmations: effective_min_confirmations,
        };

        // Content encodes the dBTC mint amount (= BTC sats, 1:1)
        let content = Self::encode_dbtc_content(btc_amount_sats);
        let creator_keypair = crate::sdk::signing_authority::derive_current_signing_keypair()?;
        let draft = self.dlv_manager.prepare_vault(
            creator_keypair.public_key(),
            condition,
            &content,
            "application/dsm-dbtc-mint",
            Some(kem_public_key.to_vec()),
            kem_public_key,
            &reference_state.hash,
        )?;
        let creator_signature = dsm::crypto::sphincs::sphincs_sign(
            creator_keypair.secret_key(),
            &draft.parameters_hash,
        )
        .map_err(|e| DsmError::crypto("sphincs_sign", Some(e)))?;

        let (vault_id_bytes, _op) = self
            .dlv_manager
            .finalize_vault(draft, &creator_signature, None, None)
            .await?;
        let vault_id = crate::util::text_id::encode_base32_crockford(&vault_id_bytes);

        let external_commitment = Self::create_deposit_commitment(
            &hash_lock,
            &vault_id,
            "btc_to_dbtc",
            btc_amount_sats,
            reference_state,
        );

        let vault_op_id = Self::generate_vault_op_id(&hash_lock, &vault_id);

        let record = VaultOperation {
            vault_op_id: vault_op_id.clone(),
            direction: VaultDirection::BtcToDbtc,
            state: VaultOpState::Initiated,
            hash_lock,
            vault_id: Some(vault_id.clone()),
            btc_amount_sats,
            btc_pubkey: claim_pubkey.to_vec(),
            htlc_script: Some(htlc_script.clone()),
            htlc_address: Some(htlc_address.clone()),
            external_commitment: Some(external_commitment),
            refund_iterations,
            created_at_state: reference_state.hash[0] as u64,
            entry_header: None,
            parent_vault_id: None,
            successor_depth: 0,
            is_fractional_successor: false,
            refund_hash_lock,
            destination_address: None,
            funding_txid: None,
            exit_header: None,
            exit_confirm_depth: 0,
            entry_txid: None,
            deposit_nonce: Some(deposit_nonce),
        };

        let mut ops = self.pending_ops.write().await;
        ops.insert(vault_op_id.clone(), record.clone());
        drop(ops);

        // Persist storage_nodely only. The live advertisement is published after entry anchoring.
        //
        // Note (audit finding §6, intentional deviation): persist_vault_storage_node_only
        // sends a pre-activation stub to storage nodes. It does NOT include the entry_txid
        // (the Bitcoin funding txid is unknown at this point). The paper (§21.1, Definition 9)
        // specifies publishing only after the vault is funded to d_min.
        // Mitigation: draw_tap()/bitcoin.deposit.complete re-publishes the full advertisement
        // (with entry_txid) after confirmation, overwriting the stub. Storage nodes that route
        // on the stub see a vault in PendingActive state and cannot produce a valid UTXO proof.
        // The deviation is acceptable for development but should be resolved before mainnet
        // by deferring the initial publish to after entry-anchor confirmation.
        Self::persist_vault_op(&record)?;
        self.persist_vault_storage_node_only(&vault_id).await?;

        Ok(DepositInitiation {
            vault_op_id,
            hash_lock,
            vault_id,
            external_commitment,
            htlc_script: Some(htlc_script),
            htlc_address: Some(htlc_address),
        })
    }

    // -----------------------------------------------------------------------
    // dBTC → BTC flow (planner-executed sweep legs)
    // -----------------------------------------------------------------------

    /// Initiate a fractional dBTC exit and create a deterministic successor vault
    /// for the remainder (sweep-and-change model).
    ///
    /// This method:
    /// - burns `exit_amount_sats` of dBTC (returned as `TokenOperation::Burn`)
    /// - creates a successor DLV containing the remaining balance
    /// - constructs successor HTLC script/address for on-chain change output
    ///
    /// Safety checks enforced:
    /// - `exit_amount_sats > 0`
    /// - `exit_amount_sats < source_amount`
    /// - remainder >= max(min_vault_balance, dust_floor)
    /// - successor_depth <= max_successor_depth
    #[allow(clippy::too_many_arguments)]
    pub async fn pour_partial(
        &self,
        source_vault_id: &str,
        policy_commit: &[u8; 32],
        source_amount_sats: u64,
        source_successor_depth: u32,
        exit_amount_sats: u64,
        refund_iterations: u64,
        reference_state: &State,
        network: BitcoinNetwork,
        kem_public_key: &[u8],
    ) -> Result<FractionalExitResult, DsmError> {
        let params = DbtcParams::resolve();
        if exit_amount_sats == 0 {
            return Err(DsmError::invalid_operation(
                "Fractional exit amount must be greater than 0",
            ));
        }
        if exit_amount_sats < params.min_exit_sats {
            return Err(DsmError::invalid_operation(format!(
                "Fractional exit below minimum: {} < {} (dust {} + fees {})",
                exit_amount_sats,
                params.min_exit_sats,
                params.dust_floor_sats,
                params.estimated_sweep_fee_sats
            )));
        }

        // Concurrent-exit guard: fast-fail if another exit is already in flight.
        {
            let ops = self.pending_ops.read().await;
            let already_exiting = ops.values().any(|r| {
                (r.parent_vault_id.as_deref() == Some(source_vault_id)
                    && r.is_fractional_successor
                    && matches!(
                        r.state,
                        VaultOpState::Initiated
                            | VaultOpState::AwaitingConfirmation
                            | VaultOpState::Claimable
                    ))
                    || (r.direction == VaultDirection::DbtcToBtc
                        && r.vault_id.as_deref() == Some(source_vault_id)
                        && matches!(
                            r.state,
                            VaultOpState::Initiated
                                | VaultOpState::Completed
                                | VaultOpState::AwaitingConfirmation
                                | VaultOpState::Claimable
                        ))
            });
            if already_exiting {
                return Err(DsmError::invalid_operation(format!(
                    "Vault {source_vault_id} already has an exit in progress; \
                     concurrent pour_partial rejected"
                )));
            }
        }
        if exit_amount_sats >= source_amount_sats {
            return Err(DsmError::invalid_operation(format!(
                "Fractional exit must be strictly less than source amount: exit={} source={}",
                exit_amount_sats, source_amount_sats
            )));
        }

        let remainder_sats = source_amount_sats - exit_amount_sats;
        let min_remainder = params.min_vault_balance_sats.max(params.dust_floor_sats);
        if remainder_sats < min_remainder {
            return Err(DsmError::BitcoinTapSafety {
                invariant: "vault_floor".to_string(),
                message: format!(
                    "Remainder {} sats below vault floor {} sats. \
                     The successor vault would be unredeemable on Bitcoin.",
                    remainder_sats, min_remainder
                ),
            });
        }

        let next_depth = source_successor_depth.saturating_add(1);
        if next_depth > params.max_successor_depth {
            return Err(DsmError::BitcoinTapSafety {
                invariant: "successor_depth".to_string(),
                message: format!(
                    "Successor depth exceeded: {} > {}",
                    next_depth, params.max_successor_depth
                ),
            });
        }

        // Bearer-derived η for successor: fresh deposit_nonce, same manifold_seed.
        // η = BLAKE3("DSM/dbtc-bearer-eta\0" || manifold_seed || deposit_nonce)
        let manifold_seed = crate::storage::client_db::get_or_create_manifold_seed(policy_commit)
            .map_err(|e| {
            DsmError::storage(format!("manifold_seed: {e}"), None::<std::io::Error>)
        })?;
        let mut successor_deposit_nonce = [0u8; 32];
        let mut os_rng = OsRng;
        os_rng.fill_bytes(&mut successor_deposit_nonce);
        let successor_eta = Self::derive_bearer_eta(&manifold_seed, &successor_deposit_nonce);
        let successor_preimage = Self::derive_preimage_from_eta(&successor_eta);
        let successor_hash_lock = sha256_hash_lock(&successor_preimage);

        // Derive refund hash lock for successor vault
        let successor_fulfillment_bytes = successor_hash_lock.to_vec();
        let successor_refund_key = dsm::crypto::blake3::domain_hash_bytes(
            "DSM/dlv-refund",
            &[
                &successor_fulfillment_bytes[..],
                &refund_iterations.to_le_bytes(),
            ]
            .concat(),
        );
        let successor_refund_hash_lock = sha256_hash_lock(&successor_refund_key);

        // Math-owned successor: derive claim pubkey from successor preimage.
        let (_, successor_claim_pubkey) = crate::sdk::bitcoin_tx_builder::derive_claim_keypair(
            &successor_preimage,
            &successor_hash_lock,
        )?;

        // Signet/Testnet: 1 confirmation; mainnet: full burial depth (dBTC §6.4).
        //
        // NON_PAPER_MODE: The paper requires d_min = 100 on all networks (§17).
        // This shortcut is intentional for development/testing only. See audit finding §5.
        let effective_min_confirmations = match network {
            BitcoinNetwork::Signet | BitcoinNetwork::Testnet => 1,
            _ => params.min_confirmations,
        };

        let successor_condition = FulfillmentMechanism::BitcoinHTLC {
            hash_lock: successor_hash_lock,
            refund_hash_lock: successor_refund_hash_lock,
            refund_iterations,
            bitcoin_pubkey: successor_claim_pubkey.to_vec(),
            expected_btc_amount_sats: remainder_sats,
            network: network.to_u32(),
            min_confirmations: effective_min_confirmations,
        };

        let successor_content = Self::encode_dbtc_content(remainder_sats);
        let creator_keypair = crate::sdk::signing_authority::derive_current_signing_keypair()?;
        let draft = self.dlv_manager.prepare_vault(
            creator_keypair.public_key(),
            successor_condition,
            &successor_content,
            "application/dsm-dbtc-successor",
            Some(kem_public_key.to_vec()),
            kem_public_key,
            &reference_state.hash,
        )?;
        let creator_signature = dsm::crypto::sphincs::sphincs_sign(
            creator_keypair.secret_key(),
            &draft.parameters_hash,
        )
        .map_err(|e| DsmError::crypto("sphincs_sign", Some(e)))?;

        let (successor_vault_id_bytes, _op) = self
            .dlv_manager
            .finalize_vault(draft, &creator_signature, None, None)
            .await?;
        let successor_vault_id =
            crate::util::text_id::encode_base32_crockford(&successor_vault_id_bytes);

        let successor_htlc_script = build_htlc_script(
            &successor_hash_lock,
            &successor_refund_hash_lock,
            &successor_claim_pubkey,
            &successor_claim_pubkey,
        )?;
        let successor_htlc_address = htlc_p2wsh_address(&successor_htlc_script, network)?;

        let external_commitment = Self::create_deposit_commitment(
            &successor_hash_lock,
            &successor_vault_id,
            "fractional_exit_successor",
            remainder_sats,
            reference_state,
        );
        let successor_vault_op_id =
            Self::generate_vault_op_id(&successor_hash_lock, &successor_vault_id);

        let successor_record = VaultOperation {
            vault_op_id: successor_vault_op_id.clone(),
            direction: VaultDirection::BtcToDbtc,
            state: VaultOpState::Initiated,
            hash_lock: successor_hash_lock,
            vault_id: Some(successor_vault_id.clone()),
            btc_amount_sats: remainder_sats,
            btc_pubkey: successor_claim_pubkey.to_vec(),
            htlc_script: Some(successor_htlc_script.clone()),
            htlc_address: Some(successor_htlc_address.clone()),
            external_commitment: Some(external_commitment),
            refund_iterations,
            created_at_state: reference_state.hash[0] as u64,
            entry_header: None,
            parent_vault_id: Some(source_vault_id.to_string()),
            successor_depth: next_depth,
            is_fractional_successor: true,
            refund_hash_lock: successor_refund_hash_lock,
            destination_address: None,
            funding_txid: None,
            exit_header: None,
            exit_confirm_depth: 0,
            entry_txid: None,
            deposit_nonce: Some(successor_deposit_nonce),
        };

        {
            let mut ops = self.pending_ops.write().await;
            // Re-check under write lock to close the race between the read pre-check
            // and here (vault creation was async — another task may have won the race).
            let already_exiting = ops.values().any(|r| {
                (r.parent_vault_id.as_deref() == Some(source_vault_id)
                    && r.is_fractional_successor
                    && matches!(
                        r.state,
                        VaultOpState::Initiated
                            | VaultOpState::AwaitingConfirmation
                            | VaultOpState::Claimable
                    ))
                    || (r.direction == VaultDirection::DbtcToBtc
                        && r.vault_id.as_deref() == Some(source_vault_id)
                        && matches!(
                            r.state,
                            VaultOpState::Initiated
                                | VaultOpState::Completed
                                | VaultOpState::AwaitingConfirmation
                                | VaultOpState::Claimable
                        ))
            });
            if already_exiting {
                return Err(DsmError::invalid_operation(format!(
                    "Vault {source_vault_id} already has an exit in progress; \
                     concurrent pour_partial rejected"
                )));
            }
            ops.insert(successor_vault_op_id.clone(), successor_record.clone());
        }

        // Persist successor deposit + vault (Invariant 18).
        // §7 Remark 2: successor advertisement is published only AFTER the sweep tx reaches
        // dmin confirmations (entry_txid = txid(txsweep)), not here. Use storage_node-only persist;
        // bitcoin.exit.complete calls update_successor_entry_txid_and_publish_ad.
        Self::persist_vault_op(&successor_record)?;
        self.persist_vault_storage_node_only(&successor_vault_id)
            .await?;

        Ok(FractionalExitResult {
            source_vault_id: source_vault_id.to_string(),
            successor_vault_id,
            successor_vault_op_id,
            exit_vault_op_id: String::new(), // handler creates after burn succeeds
            exit_amount_sats,
            remainder_sats,
            successor_depth: next_depth,
            successor_htlc_script,
            successor_htlc_address,
            token_operation: TokenOperation::Burn {
                token_id: DBTC_TOKEN_ID.to_string(),
                amount: exit_amount_sats,
            },
        })
    }

    // -----------------------------------------------------------------------
    // Deposit completion
    // -----------------------------------------------------------------------

    /// Complete an atomic deposit by providing the preimage and SPV proof.
    ///
    /// On success, returns a `DepositCompletion` containing:
    /// - For BTC→dBTC: a `TokenOperation::Mint` that mints dBTC to `recipient`
    /// - For dBTC→BTC: a `TokenOperation::Burn` that destroys the locked dBTC
    ///
    /// The caller MUST execute `completion.token_operation` via their token
    /// system to finalize the dBTC state change.
    ///
    /// # Parameters
    /// - `vault_op_id`: The deposit identifier from `DepositInitiation`
    /// - `preimage`: The secret `s` where `SHA256(s) == hash_lock`
    /// - `bitcoin_txid`: The Bitcoin transaction ID containing the HTLC
    /// - `bitcoin_tx_raw`: Raw serialized Bitcoin transaction bytes for
    ///   output amount/script verification
    /// - `spv_proof_bytes`: Serialized merkle proof of tx inclusion
    /// - `block_header`: 80-byte Bitcoin block header containing the tx
    /// - `header_chain`: Chain of PoW-validated headers; confirmation depth is derived
    ///   from `header_chain.len() + 1` (never caller-attested)
    /// - `requester_key`: Identity of the deposit claimer
    /// - `recipient`: 32-byte device ID to receive minted dBTC (for BTC→dBTC)
    /// - `reference_state`: Current DSM state
    #[allow(clippy::too_many_arguments)]
    pub async fn draw_tap(
        &self,
        vault_op_id: &str,
        preimage: &[u8],
        bitcoin_txid: [u8; 32],
        bitcoin_tx_raw: &[u8],
        spv_proof_bytes: &[u8],
        block_header: [u8; 80],
        header_chain: &[[u8; 80]],
        requester_key: &[u8],
        _signing_public_key: &[u8],
        recipient: [u8; 32],
        reference_state: &State,
        stitched_receipt: Option<Vec<u8>>,
        stitched_receipt_sigma: Option<[u8; 32]>,
    ) -> Result<DepositCompletion, DsmError> {
        // Strict fail-closed gate: deposit completion requires canonical
        // protocol-transition bytes and matching sovereign commitment.
        let stitched_receipt = stitched_receipt.ok_or_else(|| {
            DsmError::invalid_operation("draw_tap requires canonical protocol transition bytes")
        })?;
        if stitched_receipt.is_empty() {
            return Err(DsmError::invalid_operation(
                "draw_tap protocol transition bytes must be non-empty",
            ));
        }
        let stitched_receipt_sigma = stitched_receipt_sigma.ok_or_else(|| {
            DsmError::invalid_operation("draw_tap requires protocol transition commitment")
        })?;
        let computed_sigma =
            crate::sdk::receipts::compute_protocol_transition_commitment(&stitched_receipt);
        if computed_sigma != stitched_receipt_sigma {
            return Err(DsmError::invalid_operation(
                "draw_tap protocol transition commitment mismatch",
            ));
        }

        let (vault_id, direction, btc_amount_sats, expected_script_pubkey) = {
            let record = self.get_vault_record(vault_op_id).await?;

            if record.state != VaultOpState::Initiated
                && record.state != VaultOpState::AwaitingConfirmation
                && record.state != VaultOpState::Claimable
            {
                return Err(DsmError::invalid_operation(format!(
                    "Deposit {vault_op_id} is in state {:?}, cannot complete",
                    record.state
                )));
            }

            // Verify preimage matches hash_lock
            let computed = sha256_hash_lock(preimage);
            if computed != record.hash_lock {
                return Err(DsmError::invalid_operation(
                    "Preimage does not match hash lock",
                ));
            }

            let vault_id = record
                .vault_id
                .clone()
                .ok_or_else(|| DsmError::invalid_operation("Deposit has no associated vault"))?;

            // Ensure the vault is loaded into the in-memory DLV manager. Handles
            // mid-session vault ingestion (e.g., received via BLE bilateral transfer).
            self.ensure_vault_in_memory(&vault_id).await?;

            let expected_script_pubkey = if let Some(htlc_script) = &record.htlc_script {
                let script_buf = bitcoin::ScriptBuf::from(htlc_script.clone());
                bitcoin::ScriptBuf::new_p2wsh(&script_buf.wscript_hash()).to_bytes()
            } else {
                Vec::new()
            };

            (
                vault_id,
                record.direction.clone(),
                record.btc_amount_sats,
                expected_script_pubkey,
            )
        };

        // Build the fulfillment proof
        let proof = FulfillmentProof::BitcoinHTLCProof {
            preimage: preimage.to_vec(),
            bitcoin_txid,
            bitcoin_tx_raw: bitcoin_tx_raw.to_vec(),
            spv_proof: spv_proof_bytes.to_vec(),
            expected_script_pubkey,
            block_header: Box::new(block_header),
            header_chain: header_chain.to_vec(),
            stitched_receipt: Some(stitched_receipt),
            stitched_receipt_sigma: Some(stitched_receipt_sigma),
        };

        if direction != VaultDirection::BtcToDbtc {
            return Err(DsmError::invalid_operation(
                "draw_tap no longer supports dbtc_to_btc exits; use planner-driven withdrawal execution",
            ));
        }

        let vid32 = crate::util::text_id::decode_bytes32(&vault_id).ok_or_else(|| {
            DsmError::invalid_operation(format!(
                "draw_tap: vault_id {vault_id} is not a valid Base32 32-byte id"
            ))
        })?;
        let activated = self
            .dlv_manager
            .activate_vault(&vid32, proof, requester_key, &reference_state.hash)
            .await?;
        if !activated {
            return Err(DsmError::invalid_operation(
                "DLV activation failed — proof verification failed",
            ));
        }

        let unlock_op = None;
        let token_operation = TokenOperation::Mint {
            token_id: DBTC_TOKEN_ID.to_string(),
            recipient,
            amount: btc_amount_sats,
        };

        // Update deposit state and cache entry header (Invariant 19)
        {
            let mut ops = self.pending_ops.write().await;
            if let Some(record) = ops.get_mut(vault_op_id) {
                record.state = VaultOpState::Completed;
                record.entry_header = Some(block_header);
                record.entry_txid = Some(bitcoin_txid.to_vec());
            }
        }

        // Cache entry header on the vault itself (Invariant 19, §12.2.3)
        {
            if let Ok(vault_lock) = self.dlv_manager.get_vault(&vid32).await {
                let mut vault = vault_lock.lock().await;
                vault.entry_header = Some(block_header);
            }
        }

        // Persist updated deposit + vault state (Invariant 18)
        {
            let ops = self.pending_ops.read().await;
            if let Some(record) = ops.get(vault_op_id) {
                if let Err(e) = Self::persist_vault_op(record) {
                    log::warn!("Failed to persist vault record in draw_tap: {}", e);
                }
            }
        }
        if let Err(e) = self.persist_vault(&vault_id).await {
            log::warn!("Failed to persist vault in draw_tap: {}", e);
        }

        Ok(DepositCompletion {
            vault_op_id: vault_op_id.to_string(),
            preimage: preimage.to_vec(),
            vault_id,
            dlv_unlock_operation: unlock_op,
            token_operation,
        })
    }

    /// Get the preimage for a deposit where we are the initiator (BTC→dBTC direction).
    ///
    /// Returns the preimage so it can be used to claim the Bitcoin HTLC.
    /// This reveals the secret — only call when ready to claim.
    pub async fn get_claim_preimage(&self, vault_op_id: &str) -> Result<Vec<u8>, DsmError> {
        let record = self.get_vault_record(vault_op_id).await?;
        Self::derive_preimage(&record)
    }

    /// Refund an expired deposit by invalidating the DLV.
    ///
    /// Only valid after `refund_iterations` state transitions have elapsed.
    ///
    /// Planner-driven dBTC→BTC withdrawals do not use `close_tap()`.
    pub async fn close_tap(
        &self,
        vault_op_id: &str,
        reference_state: &State,
    ) -> Result<Option<TokenOperation>, DsmError> {
        let (vault_id, direction, btc_amount_sats, refund_iterations, created_at_state) = {
            let record = self.get_vault_record(vault_op_id).await?;

            if record.state == VaultOpState::Completed || record.state == VaultOpState::Refunded {
                return Err(DsmError::invalid_operation(format!(
                    "Deposit {vault_op_id} already {:?}",
                    record.state
                )));
            }

            let vault_id = record
                .vault_id
                .clone()
                .ok_or_else(|| DsmError::invalid_operation("Deposit has no associated vault"))?;

            (
                vault_id,
                record.direction.clone(),
                record.btc_amount_sats,
                record.refund_iterations,
                record.created_at_state,
            )
        };

        // Check iteration-based timeout (budget exhaustion)
        let elapsed = (reference_state.hash[0] as u64).saturating_sub(created_at_state);
        if elapsed < refund_iterations {
            return Err(DsmError::invalid_operation(format!(
                "Refund not yet available: {elapsed} iterations elapsed, need {refund_iterations}"
            )));
        }

        // Refund preimage rk_V is deterministic:
        //   rk_V = BLAKE3("DSM/dlv-refund" || hash_lock || refund_iterations_le)
        // Re-derived on demand by bitcoin.refund.build (Invariant 5: witness never at rest).
        log::info!(
            "[close_tap] Deposit {vault_op_id} timed out; \
             refund preimage will be derived on demand by bitcoin.refund.build"
        );

        let invalidation_message = [
            vault_id.as_bytes(),
            b"deposit_timeout_refund".as_slice(),
            &reference_state.hash[..],
        ]
        .concat();
        let creator_signature = dsm::crypto::sphincs::sphincs_sign(
            &crate::sdk::signing_authority::current_secret_key()?,
            &invalidation_message,
        )
        .map_err(|e| DsmError::crypto("sphincs_sign", Some(e)))?;

        // Invalidate the vault
        let vid32 = crate::util::text_id::decode_bytes32(&vault_id).ok_or_else(|| {
            DsmError::invalid_operation(format!(
                "close_tap: vault_id {vault_id} is not a valid Base32 32-byte id"
            ))
        })?;
        let _op = self
            .dlv_manager
            .invalidate_vault(
                &vid32,
                "deposit_timeout_refund",
                &creator_signature,
                &reference_state.hash,
            )
            .await?;

        // Update deposit state
        {
            let mut ops = self.pending_ops.write().await;
            if let Some(record) = ops.get_mut(vault_op_id) {
                record.state = VaultOpState::Refunded;
            }
        }

        // Persist updated deposit + vault state (Invariant 18)
        {
            let ops = self.pending_ops.read().await;
            if let Some(record) = ops.get(vault_op_id) {
                if let Err(e) = Self::persist_vault_op(record) {
                    log::warn!("Failed to persist vault record in refund_deposit: {}", e);
                }
            }
        }
        if let Err(e) = self.persist_vault(&vault_id).await {
            log::warn!("Failed to persist vault in refund_deposit: {}", e);
        }

        if direction != VaultDirection::BtcToDbtc {
            return Err(DsmError::invalid_operation(
                "close_tap no longer supports dbtc_to_btc exits",
            ));
        }

        let _ = btc_amount_sats;
        Ok(None)
    }

    /// Query the current state of a deposit
    pub async fn get_vault_op_status(&self, vault_op_id: &str) -> Result<VaultOpState, DsmError> {
        let record = self.get_vault_record(vault_op_id).await?;
        Ok(record.state.clone())
    }

    /// Get the full vault record (in-memory domain model).
    pub async fn get_vault_record(&self, vault_op_id: &str) -> Result<VaultOperation, DsmError> {
        {
            let ops = self.pending_ops.read().await;
            if let Some(rec) = ops.get(vault_op_id) {
                return Ok(rec.clone());
            }
        }

        self.load_vault_op_by_id_from_store(vault_op_id)
            .await?
            .ok_or_else(|| {
                DsmError::not_found("Deposit", Some(format!("Deposit {vault_op_id} not found")))
            })
    }

    /// Get the vault record associated with a vault ID (in-memory domain model).
    pub async fn get_vault_record_by_vault(
        &self,
        vault_id: &str,
    ) -> Result<VaultOperation, DsmError> {
        {
            let ops = self.pending_ops.read().await;
            if let Some(rec) = ops
                .values()
                .find(|r| r.vault_id.as_deref() == Some(vault_id))
            {
                return Ok(rec.clone());
            }
        }

        self.load_vault_op_by_vault_from_store(vault_id)
            .await?
            .ok_or_else(|| {
                DsmError::not_found(
                    "Deposit",
                    Some(format!("No vault record found for vault {vault_id}")),
                )
            })
    }

    /// Update the funding_txid on a vault record (both in-memory and SQLite).
    /// Called after the sweep tx is broadcast for fractional successors.
    pub async fn update_vault_record_funding_txid(
        &self,
        vault_op_id: &str,
        txid: &str,
    ) -> Result<(), DsmError> {
        // Update in-memory
        if let Some(rec) = self.pending_ops.write().await.get_mut(vault_op_id) {
            rec.funding_txid = Some(txid.to_string());
        }
        // Update SQLite
        crate::storage::client_db::update_vault_record_funding_txid(vault_op_id, txid).map_err(
            |e| DsmError::storage(format!("update funding_txid: {e}"), None::<std::io::Error>),
        )?;
        Ok(())
    }

    /// Store the exit anchor on a vault record (dBTC §6.4.3, §12.1.3).
    /// Called after the sweep/claim tx is buried under sufficient blocks.
    pub async fn update_vault_record_exit_anchor(
        &self,
        vault_op_id: &str,
        exit_header: [u8; 80],
        confirm_depth: u32,
    ) -> Result<(), DsmError> {
        // Fix #6: Defense-in-depth burial gate (dBTC spec §7 Invariant 3, §12.1.3).
        // The handler already enforces confs >= required before calling this method;
        // this SDK-layer check closes any bypass path that could mark an exit as anchored
        // before the deep-anchor depth is satisfied.
        let required = DbtcParams::resolve().min_confirmations as u32;
        if confirm_depth < required {
            return Err(DsmError::BitcoinTapSafety {
                invariant: "exit_burial_depth".to_string(),
                message: format!(
                    "Exit confirmation depth {confirm_depth} < required {required}. \
                     Cannot anchor exit until deep-burial depth is met (dBTC §7 Invariant 3)."
                ),
            });
        }
        // Update in-memory
        if let Some(rec) = self.pending_ops.write().await.get_mut(vault_op_id) {
            rec.exit_header = Some(exit_header);
            rec.exit_confirm_depth = confirm_depth;
        }
        // Update SQLite
        crate::storage::client_db::update_vault_record_exit_anchor(
            vault_op_id,
            &exit_header,
            confirm_depth,
        )
        .map_err(|e| {
            DsmError::storage(format!("update exit anchor: {e}"), None::<std::io::Error>)
        })?;
        Ok(())
    }

    /// Update in-memory vault record state and optional destination address.
    /// Called by handlers after burn succeeds to keep in-memory map in sync with SQLite.
    pub async fn update_vault_record_state_in_memory(
        &self,
        vault_op_id: &str,
        new_state: VaultOpState,
        destination_address: String,
    ) {
        let mut ops = self.pending_ops.write().await;
        if let Some(rec) = ops.get_mut(vault_op_id) {
            rec.state = new_state;
            if !destination_address.is_empty() {
                rec.destination_address = Some(destination_address);
            }
        }
    }

    /// Update the entry_txid (raw bytes) on an in-memory vault record.
    /// Called before vault publication so `get_vault_record` returns fresh data.
    pub async fn update_vault_record_entry_txid_in_memory(&self, vault_op_id: &str, txid: Vec<u8>) {
        let mut ops = self.pending_ops.write().await;
        if let Some(rec) = ops.get_mut(vault_op_id) {
            rec.entry_txid = Some(txid);
        }
    }

    /// Create and persist a DbtcToBtc exit vault record visible in `bitcoin.deposit.list`.
    /// Called by fractional exit handler after burn succeeds.
    pub async fn create_exit_deposit_record(
        &self,
        source_vault_id: &str,
        amount_sats: u64,
        destination_address: &str,
        funding_txid: &str,
    ) -> Result<String, DsmError> {
        // Look up the source deposit record to inherit hash_lock / keys
        let source_rec = self.get_vault_record_by_vault(source_vault_id).await.ok();

        let hash_lock = source_rec
            .as_ref()
            .map(|r| r.hash_lock)
            .unwrap_or([0u8; 32]);

        let exit_vault_op_id =
            Self::generate_vault_op_id(&hash_lock, &format!("exit_{source_vault_id}"));

        let exit_record = VaultOperation {
            vault_op_id: exit_vault_op_id.clone(),
            direction: VaultDirection::DbtcToBtc,
            // Start in AwaitingConfirmation so the frontend polls
            // check_confirmations for exit burial depth (dBTC §6.4.3).
            // Transitions to Completed once depth >= min_exit_confirmations.
            state: VaultOpState::AwaitingConfirmation,
            hash_lock,
            vault_id: Some(source_vault_id.to_string()),
            btc_amount_sats: amount_sats,
            btc_pubkey: source_rec
                .as_ref()
                .map(|r| r.btc_pubkey.clone())
                .unwrap_or_default(),
            htlc_script: source_rec.as_ref().and_then(|r| r.htlc_script.clone()),
            htlc_address: source_rec.as_ref().and_then(|r| r.htlc_address.clone()),
            external_commitment: None,
            refund_iterations: 0,
            created_at_state: source_rec.as_ref().map(|r| r.created_at_state).unwrap_or(0),
            entry_header: source_rec.as_ref().and_then(|r| r.entry_header),
            parent_vault_id: Some(source_vault_id.to_string()),
            successor_depth: 0,
            is_fractional_successor: false,
            refund_hash_lock: [0u8; 32],
            destination_address: if destination_address.is_empty() {
                None
            } else {
                Some(destination_address.to_string())
            },
            funding_txid: if funding_txid.is_empty() {
                None
            } else {
                Some(funding_txid.to_string())
            },
            exit_header: None,
            exit_confirm_depth: 0,
            entry_txid: None,
            deposit_nonce: source_rec.as_ref().and_then(|r| r.deposit_nonce), // carry deposit_nonce for sweep derivation
        };

        {
            let mut ops = self.pending_ops.write().await;
            ops.insert(exit_vault_op_id.clone(), exit_record.clone());
        }
        Self::persist_vault_op(&exit_record)?;
        if let Err(e) = self
            .publish_vault_advertisement_mandatory(source_vault_id)
            .await
        {
            log::warn!(
                "[create_exit_deposit_record] vault re-publication failed for {source_vault_id}: {e}"
            );
        }

        log::info!(
            "[create_exit_deposit_record] Created exit deposit {} for vault {} ({} sats)",
            exit_vault_op_id,
            source_vault_id,
            amount_sats
        );
        Ok(exit_vault_op_id)
    }

    /// Scan for fractional exits that crashed between lock and burn.
    /// Called during SDK bootstrap to detect and resolve orphaned states.
    ///
    /// For `SweepPending`: the sweep may or may not have been broadcast.
    ///   - If source UTXO is spent → sweep was broadcast → needs burn completion
    ///   - If source UTXO is unspent → sweep was not broadcast → release lock
    ///
    /// For `BurnPending`: sweep succeeded but burn didn't execute.
    ///   - The funding_txid is persisted → just needs burn completion.
    ///
    /// Returns list of recovered successor vault op IDs.
    pub fn recover_pending_fractional_exits(&self) -> Vec<String> {
        let pending = match crate::storage::client_db::list_pending_exit_burns() {
            Ok(records) => records,
            Err(e) => {
                log::warn!("[recovery] list_pending_exit_burns failed: {e}");
                return vec![];
            }
        };

        if pending.is_empty() {
            return vec![];
        }
        log::info!(
            "[recovery] Found {} pending fractional exit(s) to recover",
            pending.len()
        );

        let recovered = vec![];
        for rec in pending {
            let exit_amount = rec.exit_amount_sats;
            if exit_amount == 0 {
                log::warn!(
                    "[recovery] deposit {} has exit_amount_sats=0, skipping",
                    rec.vault_op_id
                );
                continue;
            }

            match rec.vault_state.as_str() {
                "SweepPending" => {
                    // Do NOT release locked balance on bootstrap without proving the sweep
                    // never broadcast. If the source UTXO was already spent, releasing here
                    // would resurrect value that is still genuinely in-flight.
                    //
                    // Explicit recovery must go through bitcoin.sweep.recover, which can
                    // inspect Bitcoin-side reality before deciding whether to burn-complete
                    // or fail the attempt.
                    log::warn!(
                        "[recovery] deposit {} in SweepPending — leaving locked {} sats untouched; explicit bitcoin.sweep.recover required",
                        rec.vault_op_id,
                        exit_amount,
                    );
                    continue;
                }
                "BurnPending" => {
                    // Sweep succeeded (funding_txid should be set) but burn didn't execute.
                    // We can't execute the burn here (needs wallet + state machine context)
                    // so we log a warning. The bitcoin.sweep.recover handler can complete it.
                    log::warn!(
                        "[recovery] deposit {} in BurnPending — sweep txid={:?}, burn needed. \
                         Call bitcoin.sweep.recover to complete.",
                        rec.vault_op_id,
                        rec.funding_txid,
                    );
                    // Don't release the lock — the sweep succeeded.
                    // The locked sats represent the burn that still needs to happen.
                }
                _ => continue,
            }
        }

        if !recovered.is_empty() {
            log::info!(
                "[recovery] Recovered {} pending fractional exit(s)",
                recovered.len()
            );
        }
        recovered
    }

    fn dbtc_policy_commit() -> [u8; 32] {
        *crate::policy::builtins::DBTC_POLICY_COMMIT
    }

    fn dbtc_policy_commit_b32() -> String {
        crate::util::text_id::encode_base32_crockford(&Self::dbtc_policy_commit())
    }

    fn vault_advertisement_prefix() -> String {
        format!("dbtc/manifold/{}/vault/", Self::dbtc_policy_commit_b32())
    }

    fn vault_advertisement_key(vault_id: &str) -> String {
        format!("{}{}", Self::vault_advertisement_prefix(), vault_id)
    }

    /// Mark a vault as spent on storage nodes after a successful sweep.
    ///
    /// Updates the existing advertisement's lifecycle_state to "spent" and
    /// routeable to false. Future planners skip spent vaults without
    /// hitting Bitcoin for UTXO checks.
    pub(crate) async fn mark_vault_spent_on_storage_nodes(vault_id: &str) -> Result<(), DsmError> {
        let ad_key = Self::vault_advertisement_key(vault_id);
        let ad_bytes = match Self::storage_get_bytes(&ad_key).await {
            Ok(b) => b,
            Err(e) => {
                log::warn!(
                    "[vault_spent] could not fetch advertisement for {}: {e} (skipping mark)",
                    &vault_id[..vault_id.len().min(12)]
                );
                return Ok(());
            }
        };
        let mut ad = match generated::DbtcVaultAdvertisementV1::decode(ad_bytes.as_slice()) {
            Ok(a) => a,
            Err(e) => {
                log::warn!(
                    "[vault_spent] could not decode advertisement for {}: {e} (skipping mark)",
                    &vault_id[..vault_id.len().min(12)]
                );
                return Ok(());
            }
        };
        ad.lifecycle_state = "spent".to_string();
        ad.routeable = false;
        ad.busy_reason = "UTXO spent by sweep".to_string();
        Self::storage_put_bytes(&ad_key, &ad.encode_to_vec()).await?;
        log::info!(
            "[vault_spent] marked vault {} as spent on storage nodes",
            &vault_id[..vault_id.len().min(12)]
        );
        Ok(())
    }

    /// Delete a spent vault's advertisement and proto from storage nodes.
    ///
    /// Called after settlement at dmin — the vault is economically final,
    /// the UTXO is buried, no one needs the advertisement anymore.
    /// Prevents spent vaults from accumulating on storage nodes.
    pub(crate) async fn delete_vault_from_storage_nodes(vault_id: &str) -> Result<(), DsmError> {
        let ad_key = Self::vault_advertisement_key(vault_id);
        let proto_key = Self::vault_proto_key(vault_id);
        // Best-effort delete — if it fails, the spent ad is just stale data.
        // Planners already skip it (routeable=false).
        if let Err(e) = Self::storage_delete_key(&ad_key).await {
            log::warn!(
                "[vault_prune] failed to delete advertisement for {}: {e}",
                &vault_id[..vault_id.len().min(12)]
            );
        }
        if let Err(e) = Self::storage_delete_key(&proto_key).await {
            log::warn!(
                "[vault_prune] failed to delete proto for {}: {e}",
                &vault_id[..vault_id.len().min(12)]
            );
        }
        log::info!(
            "[vault_prune] deleted spent vault {} from storage nodes",
            &vault_id[..vault_id.len().min(12)]
        );
        Ok(())
    }

    fn vault_proto_key(vault_id: &str) -> String {
        format!(
            "dbtc/manifold/{}/vault-proto/{}",
            Self::dbtc_policy_commit_b32(),
            vault_id
        )
    }

    /// Purge ALL vault data from storage nodes and local SQLite.
    /// Deletes every vault advertisement and proto under the current AND any known
    /// stale manifold prefixes (from prior policy commits), then wipes local
    /// vault_store, vault_records, in_flight_withdrawals, in_flight_withdrawal_legs,
    /// dBTC token_balances, and dlv_receipts.
    /// Also clears in-memory pending_ops.
    ///
    /// Use after policy commit migration or to reset dBTC state to zero.
    pub async fn purge_all_vault_data(&self) -> Result<PurgeResult, DsmError> {
        let mut remote_deleted = 0u32;
        let mut remote_failed = 0u32;

        // Pre-5cb45ac policy commit (old HTLC script with CLTV dead-man path).
        // Ads stored under this prefix are orphaned after the policy commit migration.
        const STALE_POLICY_COMMIT: [u8; 32] = [
            0xac, 0x14, 0x12, 0x34, 0xeb, 0x83, 0xb6, 0x75, 0xbf, 0x9d, 0xfa, 0xb2, 0x54, 0x75,
            0x0a, 0x07, 0x04, 0xc9, 0x47, 0xb7, 0x11, 0x4b, 0x96, 0xcc, 0x5f, 0x6b, 0xe5, 0x2d,
            0x82, 0x94, 0xff, 0xb8,
        ];

        let current_prefix = Self::vault_advertisement_prefix();
        let stale_b32 = crate::util::text_id::encode_base32_crockford(&STALE_POLICY_COMMIT);
        let stale_ad_prefix = format!("dbtc/manifold/{stale_b32}/vault/");
        let stale_proto_prefix = format!("dbtc/manifold/{stale_b32}/vault-proto/");

        // Collect all prefixes to sweep: current manifold + stale manifold (ad + proto).
        let prefixes_to_sweep = [
            current_prefix.clone(),
            format!(
                "dbtc/manifold/{}/vault-proto/",
                Self::dbtc_policy_commit_b32()
            ),
            stale_ad_prefix,
            stale_proto_prefix,
        ];

        // 1. List and delete all objects under each prefix on storage nodes.
        for prefix in &prefixes_to_sweep {
            let mut cursor: Option<String> = None;
            loop {
                let resp =
                    Self::storage_list_objects(prefix, cursor.as_deref(), DBTC_MANIFOLD_LIST_LIMIT)
                        .await;
                let resp = match resp {
                    Ok(r) => r,
                    Err(e) => {
                        log::warn!("[purge] storage_list_objects({prefix}) failed: {e}");
                        break;
                    }
                };
                if resp.items.is_empty() {
                    break;
                }
                for item in &resp.items {
                    match Self::storage_delete_key(&item.key).await {
                        Ok(()) => remote_deleted += 1,
                        Err(e) => {
                            log::warn!("[purge] failed to delete {}: {e}", item.key);
                            remote_failed += 1;
                        }
                    }
                }
                match resp.next_cursor {
                    Some(ref c) if !c.is_empty() => cursor = resp.next_cursor,
                    _ => break,
                }
            }
        }

        // 2. Wipe local SQLite vault/dBTC tables.
        let local_rows = crate::storage::client_db::wipe_all_vault_data().map_err(|e| {
            DsmError::storage(
                format!("wipe_all_vault_data SQLite: {e}"),
                None::<std::io::Error>,
            )
        })?;

        // 3. Clear in-memory pending_ops.
        {
            let mut ops = self.pending_ops.write().await;
            ops.clear();
        }

        log::info!(
            "[purge] complete: {remote_deleted} remote objects deleted ({remote_failed} failed), \
             {local_rows} local SQLite rows deleted"
        );

        Ok(PurgeResult {
            remote_deleted,
            remote_failed,
            local_rows_deleted: local_rows,
        })
    }

    #[cfg(test)]
    pub(crate) fn reset_dbtc_storage_test_state() {
        let mut state = dbtc_storage_test_state();
        *state = DbtcStorageTestState::default();
    }

    #[cfg(test)]
    pub(crate) fn seed_dbtc_storage_object(key: impl Into<String>, payload: Vec<u8>) {
        dbtc_storage_test_state()
            .object_store
            .insert(key.into(), payload);
    }

    #[cfg(test)]
    pub(crate) fn set_dbtc_storage_list_results(
        results: impl IntoIterator<Item = Result<generated::ObjectListResponseV1, String>>,
    ) {
        let mut state = dbtc_storage_test_state();
        state.list_results.clear();
        state.list_results.extend(results);
    }

    #[cfg(test)]
    pub(crate) fn set_dbtc_storage_put_failure(key: impl Into<String>, message: impl Into<String>) {
        dbtc_storage_test_state()
            .put_failures
            .insert(key.into(), message.into());
    }

    #[cfg(test)]
    pub(crate) fn set_dbtc_storage_get_failure(key: impl Into<String>, message: impl Into<String>) {
        dbtc_storage_test_state()
            .get_failures
            .insert(key.into(), message.into());
    }

    /// Resolve device auth credentials for storage node writes.
    /// Looks up device_id + genesis from AppState, then fetches the auth token from SQLite.
    /// Returns None (with a warning) if credentials are unavailable — callers should
    /// still attempt the request unauthenticated so that regtest/dev flows work.
    fn resolve_storage_auth(
        node_url: &str,
    ) -> Option<crate::sdk::storage_node_sdk::StorageAuthContext> {
        let device_id = crate::sdk::app_state::AppState::get_device_id()?;
        let genesis = crate::sdk::app_state::AppState::get_genesis_hash()?;
        let device_id_b32 = crate::util::text_id::encode_base32_crockford(&device_id);
        let genesis_b32 = crate::util::text_id::encode_base32_crockford(&genesis);
        let token =
            match crate::storage::client_db::get_auth_token(node_url, &device_id_b32, &genesis_b32)
            {
                Ok(Some(t)) => t,
                Ok(None) => {
                    log::debug!(
                    "[storage_auth] no auth token for node={} device={} (device not registered?)",
                    &node_url[..node_url.len().min(40)],
                    &device_id_b32[..device_id_b32.len().min(12)]
                );
                    return None;
                }
                Err(e) => {
                    log::warn!("[storage_auth] auth token lookup failed: {e}");
                    return None;
                }
            };
        Some(crate::sdk::storage_node_sdk::StorageAuthContext {
            device_id_b32,
            token_b32: token,
        })
    }

    pub(crate) async fn storage_put_bytes(key: &str, payload: &[u8]) -> Result<String, DsmError> {
        #[cfg(any(test, feature = "demos"))]
        {
            let mut state = dbtc_storage_test_state();
            if let Some(message) = state.put_failures.remove(key) {
                return Err(DsmError::storage(
                    format!("store {key}: {message}"),
                    None::<std::io::Error>,
                ));
            }
            state.object_store.insert(key.to_string(), payload.to_vec());
            Ok(key.to_string())
        }

        #[cfg(not(any(test, feature = "demos")))]
        {
            let config = crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config()
                .await
                .map_err(|e| {
                    DsmError::storage(
                        format!("load storage node config: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
            let sdk = crate::sdk::storage_node_sdk::StorageNodeSDK::new(config.clone())
                .await
                .map_err(|e| {
                    DsmError::storage(
                        format!("construct storage node sdk: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
            let node_url = config.node_urls.first().cloned().unwrap_or_default();
            let sdk = match Self::resolve_storage_auth(&node_url) {
                Some(auth) => sdk.with_auth(auth),
                None => sdk,
            };
            sdk.store_data(key, payload).await
        }
    }

    pub(crate) async fn storage_get_bytes(key: &str) -> Result<Vec<u8>, DsmError> {
        #[cfg(any(test, feature = "demos"))]
        {
            let mut state = dbtc_storage_test_state();
            if let Some(message) = state.get_failures.remove(key) {
                return Err(DsmError::storage(
                    format!("load {key}: {message}"),
                    None::<std::io::Error>,
                ));
            }
            state.object_store.get(key).cloned().ok_or_else(|| {
                DsmError::storage(
                    format!("load {key}: object not found"),
                    None::<std::io::Error>,
                )
            })
        }

        #[cfg(not(any(test, feature = "demos")))]
        {
            let config = crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config()
                .await
                .map_err(|e| {
                    DsmError::storage(
                        format!("load storage node config: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
            let sdk = crate::sdk::storage_node_sdk::StorageNodeSDK::new(config)
                .await
                .map_err(|e| {
                    DsmError::storage(
                        format!("construct storage node sdk: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
            sdk.get(key).await
        }
    }

    pub(crate) async fn storage_delete_key(key: &str) -> Result<(), DsmError> {
        #[cfg(any(test, feature = "demos"))]
        {
            let mut state = dbtc_storage_test_state();
            state.object_store.remove(key);
            Ok(())
        }

        #[cfg(not(any(test, feature = "demos")))]
        {
            let config = crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config()
                .await
                .map_err(|e| {
                    DsmError::storage(
                        format!("load storage node config: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
            let sdk = crate::sdk::storage_node_sdk::StorageNodeSDK::new(config.clone())
                .await
                .map_err(|e| {
                    DsmError::storage(
                        format!("construct storage node sdk: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
            let node_url = config.node_urls.first().cloned().unwrap_or_default();
            let sdk = match Self::resolve_storage_auth(&node_url) {
                Some(auth) => sdk.with_auth(auth),
                None => sdk,
            };
            sdk.delete(key).await
        }
    }

    pub(crate) async fn storage_list_objects(
        prefix: &str,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<generated::ObjectListResponseV1, DsmError> {
        #[cfg(any(test, feature = "demos"))]
        {
            let mut state = dbtc_storage_test_state();
            if let Some(result) = state.list_results.pop_front() {
                return result.map_err(|message| {
                    DsmError::storage(format!("list {prefix}: {message}"), None::<std::io::Error>)
                });
            }

            let mut keys: Vec<String> = state
                .object_store
                .keys()
                .filter(|key| key.starts_with(prefix))
                .cloned()
                .collect();
            keys.sort();
            if let Some(cursor) = cursor {
                keys.retain(|key| key.as_str() > cursor);
            }
            let page_keys: Vec<String> = keys
                .into_iter()
                .take(limit.clamp(1, 1000) as usize)
                .collect();
            let items = page_keys
                .iter()
                .map(|key| generated::ObjectListItemV1 {
                    key: key.clone(),
                    dlv_id_b32: String::new(),
                    size_bytes: state
                        .object_store
                        .get(key)
                        .map(|payload| payload.len() as i64)
                        .unwrap_or(0),
                })
                .collect();
            Ok(generated::ObjectListResponseV1 {
                next_cursor: page_keys.last().cloned(),
                items,
            })
        }

        #[cfg(not(any(test, feature = "demos")))]
        {
            let config = crate::sdk::storage_node_sdk::StorageNodeConfig::from_env_config()
                .await
                .map_err(|e| {
                    DsmError::storage(
                        format!("load storage node config: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
            let sdk = crate::sdk::storage_node_sdk::StorageNodeSDK::new(config)
                .await
                .map_err(|e| {
                    DsmError::storage(
                        format!("construct storage node sdk: {e}"),
                        None::<std::io::Error>,
                    )
                })?;
            let response = sdk.list_objects(prefix, cursor, limit).await?;
            Ok(generated::ObjectListResponseV1 {
                items: response
                    .items
                    .into_iter()
                    .map(|item| generated::ObjectListItemV1 {
                        key: item.key,
                        dlv_id_b32: item.dlv_id_b32,
                        size_bytes: item.size_bytes,
                    })
                    .collect(),
                next_cursor: response.next_cursor,
            })
        }
    }

    fn load_storage_node_vault_routing_inventory(
    ) -> Result<StorageNodeVaultRoutingInventory, DsmError> {
        let persisted_records =
            crate::storage::client_db::list_vault_records_db().map_err(|e| {
                DsmError::storage(
                    format!("list vault records for withdrawal planning: {e}"),
                    None::<std::io::Error>,
                )
            })?;
        let mut records_by_vault: HashMap<
            String,
            Vec<crate::storage::client_db::PersistedVaultRecord>,
        > = HashMap::new();
        let mut records_by_parent: HashMap<
            String,
            Vec<crate::storage::client_db::PersistedVaultRecord>,
        > = HashMap::new();
        for record in persisted_records {
            if let Some(vault_id) = &record.vault_id {
                records_by_vault
                    .entry(vault_id.clone())
                    .or_default()
                    .push(record.clone());
            }
            if let Some(parent_vault_id) = &record.parent_vault_id {
                records_by_parent
                    .entry(parent_vault_id.clone())
                    .or_default()
                    .push(record);
            }
        }

        let storage_node_vault_ids: HashSet<String> =
            crate::storage::client_db::list_all_vault_ids()
                .map_err(|e| {
                    DsmError::storage(
                        format!("list vault store for withdrawal planning: {e}"),
                        None::<std::io::Error>,
                    )
                })?
                .into_iter()
                .collect();

        Ok(StorageNodeVaultRoutingInventory {
            records_by_vault,
            records_by_parent,
            storage_node_vault_ids,
        })
    }

    fn proto_vault_state_label(proto: &generated::LimboVaultProto) -> &'static str {
        match proto.state.as_ref().and_then(|state| state.kind.as_ref()) {
            Some(generated::vault_state_proto::Kind::Limbo(_)) | None => "limbo",
            Some(generated::vault_state_proto::Kind::Unlocked(_)) => "unlocked",
            Some(generated::vault_state_proto::Kind::Claimed(_)) => "claimed",
            Some(generated::vault_state_proto::Kind::Invalidated(_)) => "invalidated",
        }
    }

    fn build_storage_node_vault_routing_view_from_inventory(
        vault_id: &str,
        inventory: &StorageNodeVaultRoutingInventory,
    ) -> Result<Option<StorageNodeVaultRoutingView>, DsmError> {
        let Some((proto_bytes, sqlite_state, _entry_header, _sqlite_amount_sats)) =
            crate::storage::client_db::get_vault(vault_id).map_err(|e| {
                DsmError::storage(
                    format!("load vault {vault_id} from store: {e}"),
                    None::<std::io::Error>,
                )
            })?
        else {
            return Ok(None);
        };

        let proto = generated::LimboVaultProto::decode(proto_bytes.as_slice()).map_err(|e| {
            DsmError::serialization_error("LimboVaultProto", "decode", Some(vault_id), Some(e))
        })?;

        let proto_state = Self::proto_vault_state_label(&proto);
        let lifecycle_state = if sqlite_state.trim().is_empty() {
            proto_state.to_string()
        } else if sqlite_state.trim() == "active" && proto_state == "limbo" {
            "active".to_string()
        } else {
            sqlite_state.trim().to_string()
        };

        let vault_amount = match proto
            .fulfillment_condition
            .as_ref()
            .and_then(|cond| cond.kind.as_ref())
        {
            Some(generated::fulfillment_mechanism::Kind::BitcoinHtlc(htlc)) => {
                htlc.expected_btc_amount_sats
            }
            _ => 0,
        };

        let vault_records = inventory
            .records_by_vault
            .get(vault_id)
            .cloned()
            .unwrap_or_default();
        let child_records = inventory
            .records_by_parent
            .get(vault_id)
            .cloned()
            .unwrap_or_default();

        let backing_record = vault_records
            .iter()
            .filter(|record| record.direction == "btc_to_dbtc" || record.direction == "dbtc_to_btc")
            .max_by_key(|record| record.created_at_state)
            .cloned();

        let amount_sats = backing_record
            .as_ref()
            .map(|record| record.btc_amount_sats)
            .unwrap_or(vault_amount);
        let successor_depth = backing_record
            .as_ref()
            .map(|record| record.successor_depth)
            .unwrap_or(0);

        // dBTC spec §12 (Withdrawal Planning): any vault on the policy-compatible
        // grid with a live UTXO is eligible. storage_node vault records are creator
        // bookkeeping, not withdrawal gates. Storage-discovered vaults cached
        // storage_nodely have no vault record — that is correct and expected.
        // UTXO liveness is verified at execution time, not planning time.
        let busy_reason = if lifecycle_state != "active" {
            Some(format!("Vault state is {lifecycle_state}, not active"))
        } else if amount_sats == 0 {
            Some("Vault has no withdrawable BTC".to_string())
        } else if backing_record.is_some() {
            Self::busy_vault_reason(&vault_records, &child_records)
        } else {
            None // No storage_node vault record — vault eligible via grid discovery (dBTC spec §12)
        };

        let updated_state_number = std::iter::once(proto.created_at_state)
            .chain(backing_record.iter().map(|record| record.created_at_state))
            .chain(child_records.iter().map(|record| record.created_at_state))
            .max()
            .unwrap_or(0);

        let entry_txid = backing_record
            .as_ref()
            .and_then(|record| record.entry_txid.clone());

        let htlc_address = backing_record
            .as_ref()
            .and_then(|record| record.htlc_address.clone());

        // spec Definition 9: script_commit = BLAKE3("DSM/script-commit" || htlc_script)
        let script_commit = backing_record
            .as_ref()
            .and_then(|record| record.htlc_script.as_ref())
            .map(|script| {
                dsm::crypto::blake3::domain_hash_bytes("DSM/script-commit", script).to_vec()
            });

        // spec Definition 9/11: redeem_params = public construction data for HTLC spend
        let redeem_params = backing_record.as_ref().and_then(|record| {
            let htlc_script = record.htlc_script.as_ref()?;
            let params = generated::DbtcRedeemParams {
                htlc_script: htlc_script.clone(),
                claim_pubkey: record.btc_pubkey.clone(),
                hash_lock: record.hash_lock.clone(),
                refund_hash_lock: record.refund_hash_lock.clone(),
                refund_iterations: record.refund_iterations as u32,
            };
            Some(params.encode_to_vec())
        });

        Ok(Some(StorageNodeVaultRoutingView {
            vault_id: vault_id.to_string(),
            amount_sats,
            successor_depth,
            lifecycle_state,
            routeable: busy_reason.is_none(),
            busy_reason,
            updated_state_number,
            vault_proto_bytes: proto_bytes,
            entry_txid,
            htlc_address,
            script_commit,
            redeem_params,
            deposit_nonce: backing_record
                .as_ref()
                .and_then(|record| record.deposit_nonce.clone()),
        }))
    }

    fn advertisement_block_reason(advertisement: &generated::DbtcVaultAdvertisementV1) -> String {
        if !advertisement.busy_reason.trim().is_empty() {
            advertisement.busy_reason.clone()
        } else if !advertisement.lifecycle_state.trim().is_empty() {
            format!(
                "Vault state is {}, not routeable",
                advertisement.lifecycle_state.trim()
            )
        } else {
            "Vault is not routeable".to_string()
        }
    }

    fn validate_storage_node_advertisement_against_view(
        advertisement: &generated::DbtcVaultAdvertisementV1,
        storage_node_view: &StorageNodeVaultRoutingView,
    ) -> Option<String> {
        if advertisement.amount_sats != storage_node_view.amount_sats {
            return Some("Advertisement amount does not match storage_node state".to_string());
        }
        if advertisement.successor_depth != storage_node_view.successor_depth {
            return Some(
                "Advertisement successor depth does not match storage_node state".to_string(),
            );
        }
        if advertisement.lifecycle_state != storage_node_view.lifecycle_state {
            return Some(
                "Advertisement lifecycle state does not match storage_node state".to_string(),
            );
        }
        if advertisement.routeable != storage_node_view.routeable {
            return Some(
                "Advertisement routeability does not match storage_node state".to_string(),
            );
        }
        if !advertisement.routeable
            && advertisement.busy_reason
                != storage_node_view.busy_reason.clone().unwrap_or_default()
        {
            return Some("Advertisement busy reason does not match storage_node state".to_string());
        }
        None
    }

    fn build_vault_advertisement(
        storage_node_view: &StorageNodeVaultRoutingView,
        controller_device_id: &[u8; 32],
    ) -> generated::DbtcVaultAdvertisementV1 {
        generated::DbtcVaultAdvertisementV1 {
            version: DBTC_VAULT_ADVERTISEMENT_VERSION,
            policy_commit: Self::dbtc_policy_commit().to_vec(),
            vault_id: storage_node_view.vault_id.clone(),
            controller_device_id: controller_device_id.to_vec(),
            amount_sats: storage_node_view.amount_sats,
            successor_depth: storage_node_view.successor_depth,
            lifecycle_state: storage_node_view.lifecycle_state.clone(),
            routeable: storage_node_view.routeable,
            busy_reason: storage_node_view.busy_reason.clone().unwrap_or_default(),
            updated_state_number: storage_node_view.updated_state_number,
            vault_proto_key: Self::vault_proto_key(&storage_node_view.vault_id),
            vault_proto_digest: dsm::crypto::blake3::domain_hash(
                "DSM/vault-ad",
                &storage_node_view.vault_proto_bytes,
            )
            .as_bytes()
            .to_vec(),
            entry_txid: storage_node_view.entry_txid.clone().unwrap_or_default(),
            htlc_address: storage_node_view.htlc_address.clone().unwrap_or_default(),
            script_commit: storage_node_view.script_commit.clone().unwrap_or_default(),
            redeem_params: storage_node_view.redeem_params.clone().unwrap_or_default(),
            deposit_nonce: storage_node_view.deposit_nonce.clone().unwrap_or_default(),
        }
    }

    async fn publish_storage_node_vault_advertisement_from_inventory(
        vault_id: &str,
        controller_device_id: &[u8; 32],
        inventory: &StorageNodeVaultRoutingInventory,
    ) -> Result<(), DsmError> {
        let Some(storage_node_view) =
            Self::build_storage_node_vault_routing_view_from_inventory(vault_id, inventory)?
        else {
            return Ok(());
        };
        // Guard: only the vault creator should publish advertisements.
        // If this vault has no PersistedVaultRecord in the local inventory,
        // this device received the vault via bilateral transfer and cached
        // the proto locally for execution. The creator already published the
        // complete advertisement (htlc_address, redeem_params, deposit_nonce,
        // etc.) to the replica set at deposit time. Overwriting it with our
        // incomplete local data would nuke the creator's good metadata.
        // The tokens are the key — storage nodes have everything else.
        if !inventory.records_by_vault.contains_key(vault_id) {
            log::info!(
                "[withdraw.plan] skipping advertisement publish for vault {} — \
                 no local vault record (received via transfer, not creator)",
                &vault_id[..vault_id.len().min(12)],
            );
            return Ok(());
        }
        let advertisement =
            Self::build_vault_advertisement(&storage_node_view, controller_device_id);
        // Guard: never publish an advertisement with empty htlc_address for an active vault.
        // An empty htlc_address means the PersistedVaultRecord is missing from SQLite
        // (backing_record was None during view construction). Publishing this would
        // overwrite a good advertisement on storage nodes with a broken one.
        if advertisement.lifecycle_state == "active"
            && (advertisement.htlc_address.is_empty()
                || advertisement.redeem_params.is_empty()
                || advertisement.deposit_nonce.is_empty())
        {
            return Err(DsmError::invalid_operation(format!(
                "[vault_ad] refusing to publish incomplete advertisement for vault {} — \
                 htlc_address={} redeem_params={} deposit_nonce={} \
                 (vault record missing from SQLite during refresh?)",
                &storage_node_view.vault_id[..storage_node_view.vault_id.len().min(12)],
                !advertisement.htlc_address.is_empty(),
                !advertisement.redeem_params.is_empty(),
                !advertisement.deposit_nonce.is_empty(),
            )));
        }
        let advertisement_bytes = advertisement.encode_to_vec();
        Self::storage_put_bytes(
            &advertisement.vault_proto_key,
            &storage_node_view.vault_proto_bytes,
        )
        .await?;
        Self::storage_put_bytes(
            &Self::vault_advertisement_key(&storage_node_view.vault_id),
            &advertisement_bytes,
        )
        .await?;
        Ok(())
    }

    pub(crate) async fn refresh_storage_node_vault_advertisements(
        &self,
        controller_device_id: &[u8; 32],
    ) -> Result<(), DsmError> {
        let inventory = Self::load_storage_node_vault_routing_inventory()?;
        let mut vault_ids: Vec<String> = inventory.storage_node_vault_ids.iter().cloned().collect();
        vault_ids.sort();
        log::info!(
            "[withdraw.plan] refreshing {} storage_node vault advertisements",
            vault_ids.len(),
        );
        let mut refreshed = 0u32;
        for vault_id in &vault_ids {
            match Self::publish_storage_node_vault_advertisement_from_inventory(
                vault_id,
                controller_device_id,
                &inventory,
            )
            .await
            {
                Ok(()) => {
                    refreshed += 1;
                }
                Err(e) => {
                    log::warn!(
                        "[withdraw.plan] failed to refresh advertisement for vault {}: {e}",
                        &vault_id[..vault_id.len().min(12)],
                    );
                }
            }
        }
        log::info!(
            "[withdraw.plan] refreshed {refreshed}/{} vault advertisements",
            vault_ids.len(),
        );
        Ok(())
    }

    pub(crate) async fn publish_vault_advertisement(
        &self,
        vault_id: &str,
        controller_device_id: &[u8; 32],
    ) -> Result<(), DsmError> {
        let inventory = Self::load_storage_node_vault_routing_inventory()?;
        Self::publish_storage_node_vault_advertisement_from_inventory(
            vault_id,
            controller_device_id,
            &inventory,
        )
        .await
    }

    /// §10.4 Step 7 + §7 Remark 2: After the sweep tx reaches dmin confirmations,
    /// stamp the successor vault's entry_txid with the sweep txid and publish its ad.
    ///
    /// Called from bitcoin.exit.complete once the exit deposit reaches dmin depth.
    pub async fn update_successor_entry_txid_and_publish_ad(
        &self,
        source_vault_id: &str,
        sweep_txid_bytes: &[u8; 32],
        controller_device_id: &[u8; 32],
    ) -> Result<(), DsmError> {
        // Find the fractional successor vault record whose parent is source_vault_id.
        let successor =
            crate::storage::client_db::get_fractional_successor_by_parent(source_vault_id)
                .map_err(|e| {
                    DsmError::storage(
                        format!("successor lookup for parent {source_vault_id} failed: {e}"),
                        None::<std::io::Error>,
                    )
                })?;

        let successor = match successor {
            Some(s) => s,
            None => {
                // No fractional successor — this is a full drain, no successor ad needed.
                log::debug!(
                    "[successor_ad] no fractional successor for {source_vault_id}, skipping"
                );
                return Ok(());
            }
        };

        let successor_vault_op_id = successor.vault_op_id.clone();
        let successor_vault_id = match &successor.vault_id {
            Some(v) if !v.is_empty() => v.clone(),
            _ => {
                log::warn!(
                    "[successor_ad] successor deposit {successor_vault_op_id} has no vault_id, skipping"
                );
                return Ok(());
            }
        };

        // Persist sweep txid as the successor's entry_txid (the sweep tx funds the successor HTLC).
        crate::storage::client_db::update_vault_record_entry_txid(
            &successor_vault_op_id,
            sweep_txid_bytes.as_slice(),
        )
        .map_err(|e| {
            DsmError::storage(
                format!("update_vault_record_entry_txid for {successor_vault_op_id}: {e}"),
                None::<std::io::Error>,
            )
        })?;

        // Update in-memory record.
        if let Some(rec) = self
            .pending_ops
            .write()
            .await
            .get_mut(&successor_vault_op_id)
        {
            rec.entry_txid = Some(sweep_txid_bytes.to_vec());
        }

        // Publish the successor advertisement with the correct entry_txid.
        self.publish_vault_advertisement(&successor_vault_id, controller_device_id)
            .await
            .map_err(|e| {
                DsmError::storage(
                    format!("successor ad publish for {successor_vault_id}: {e}"),
                    None::<std::io::Error>,
                )
            })?;

        log::info!(
            "[successor_ad] published successor vault {} with sweep entry_txid",
            successor_vault_id
        );
        Ok(())
    }

    async fn load_global_vault_advertisements(
        &self,
    ) -> Result<Vec<PublishedVaultAdvertisement>, DsmError> {
        let prefix = Self::vault_advertisement_prefix();
        log::info!("[withdraw.plan] fetching vault advertisements with prefix='{prefix}'");
        let mut cursor: Option<String> = None;
        let mut fetched = Vec::new();

        loop {
            let resp =
                Self::storage_list_objects(&prefix, cursor.as_deref(), DBTC_MANIFOLD_LIST_LIMIT)
                    .await?;
            let page_len = resp.items.len();
            log::info!(
                "[withdraw.plan] storage_list_objects returned {} items (cursor={:?})",
                page_len,
                cursor,
            );
            for item in resp.items {
                let payload = Self::storage_get_bytes(&item.key).await?;
                let advertisement = generated::DbtcVaultAdvertisementV1::decode(payload.as_slice())
                    .map_err(|e| {
                        DsmError::serialization_error(
                            "DbtcVaultAdvertisementV1",
                            "decode",
                            Some(item.key.clone()),
                            Some(e),
                        )
                    })?;
                log::info!(
                    "[withdraw.plan]   ad: vault={} amount={}sats routeable={} state={} depth={} busy='{}'",
                    &advertisement.vault_id[..advertisement.vault_id.len().min(12)],
                    advertisement.amount_sats,
                    advertisement.routeable,
                    advertisement.lifecycle_state,
                    advertisement.successor_depth,
                    advertisement.busy_reason,
                );
                fetched.push(PublishedVaultAdvertisement {
                    key: item.key,
                    advertisement,
                });
            }
            if page_len < DBTC_MANIFOLD_LIST_LIMIT as usize {
                break;
            }
            cursor = resp.next_cursor;
            if cursor.is_none() {
                break;
            }
        }

        fetched.sort_by(|left, right| left.key.cmp(&right.key));
        let mut deduped: HashMap<String, PublishedVaultAdvertisement> = HashMap::new();
        for entry in fetched {
            let dedupe_key = if entry.advertisement.vault_id.is_empty() {
                entry.key.clone()
            } else {
                entry.advertisement.vault_id.clone()
            };
            let replace = match deduped.get(&dedupe_key) {
                None => true,
                Some(current) => {
                    entry.advertisement.updated_state_number
                        > current.advertisement.updated_state_number
                        || (entry.advertisement.updated_state_number
                            == current.advertisement.updated_state_number
                            && entry.key < current.key)
                }
            };
            if replace {
                deduped.insert(dedupe_key, entry);
            }
        }

        let mut advertisements: Vec<PublishedVaultAdvertisement> = deduped.into_values().collect();
        advertisements.sort_by(|left, right| {
            left.advertisement
                .vault_id
                .cmp(&right.advertisement.vault_id)
                .then(left.key.cmp(&right.key))
        });
        log::info!(
            "[withdraw.plan] loaded {} vault advertisements from storage nodes",
            advertisements.len(),
        );
        Ok(advertisements)
    }

    async fn verify_remote_vault_artifacts(
        advertisement: &generated::DbtcVaultAdvertisementV1,
    ) -> Result<(), DsmError> {
        if advertisement.vault_proto_key.trim().is_empty() {
            return Err(DsmError::invalid_operation(
                "published vault artifact missing",
            ));
        }
        if advertisement.vault_proto_digest.len() != 32 {
            return Err(DsmError::invalid_operation(
                "published vault artifact digest must be 32 bytes",
            ));
        }

        let payload = Self::storage_get_bytes(&advertisement.vault_proto_key).await?;
        let digest = dsm::crypto::blake3::domain_hash("DSM/vault-ad", &payload);
        if digest.as_bytes() != advertisement.vault_proto_digest.as_slice() {
            return Err(DsmError::invalid_operation(
                "published vault artifact digest mismatch",
            ));
        }

        let proto = generated::LimboVaultProto::decode(payload.as_slice()).map_err(|e| {
            DsmError::serialization_error(
                "LimboVaultProto",
                "decode",
                Some(advertisement.vault_proto_key.clone()),
                Some(e),
            )
        })?;
        let ad_vault_id_bytes = crate::util::text_id::decode_bytes32(&advertisement.vault_id)
            .ok_or_else(|| {
                DsmError::invalid_operation(
                    "advertisement vault_id is not a valid Base32 32-byte id",
                )
            })?;
        if proto.id.as_slice() != ad_vault_id_bytes.as_slice() {
            return Err(DsmError::invalid_operation(
                "published vault artifact id mismatch",
            ));
        }
        match proto
            .fulfillment_condition
            .as_ref()
            .and_then(|cond| cond.kind.as_ref())
        {
            Some(generated::fulfillment_mechanism::Kind::BitcoinHtlc(htlc))
                if htlc.expected_btc_amount_sats == advertisement.amount_sats => {}
            Some(generated::fulfillment_mechanism::Kind::BitcoinHtlc(_)) => {
                return Err(DsmError::invalid_operation(
                    "published vault artifact amount mismatch",
                ));
            }
            _ => {
                return Err(DsmError::invalid_operation(
                    "published vault artifact is not BitcoinHTLC",
                ));
            }
        }

        // Vault liveness verified against Bitcoin at execution time (UTXO check
        // in sweep_and_broadcast). No proof blobs — token balance authorizes,
        // Bitcoin confirms. See DbtcVaultAdvertisementV1.entry_txid.

        Ok(())
    }

    async fn build_global_selector_input(
        &self,
        mempool: Option<&crate::handlers::mempool_api::MempoolClient>,
        chain_tip: Option<u64>,
    ) -> Result<WithdrawalSelectorInput, DsmError> {
        let inventory = Self::load_storage_node_vault_routing_inventory()?;
        let params = DbtcParams::resolve();
        let expected_policy_commit = Self::dbtc_policy_commit();
        let advertisements = self.load_global_vault_advertisements().await?;

        let mut eligible = Vec::new();
        let mut blocked = Vec::new();
        let mut eligible_advertisements = Vec::new();

        for published in advertisements {
            let advertisement = published.advertisement;
            let vault_id = if advertisement.vault_id.is_empty() {
                published.key
            } else {
                advertisement.vault_id.clone()
            };

            if advertisement.policy_commit.as_slice() != &expected_policy_commit[..] {
                log::warn!(
                    "[withdraw.plan] policy mismatch for vault {}: ad_policy={}bytes expected={}bytes",
                    &vault_id[..vault_id.len().min(12)],
                    advertisement.policy_commit.len(),
                    expected_policy_commit.len(),
                );
                blocked.push(WithdrawalBlockedVault {
                    vault_id,
                    amount_sats: advertisement.amount_sats,
                    reason: "Advertisement policy commit does not match dBTC manifold".to_string(),
                });
                continue;
            }

            if advertisement.amount_sats == 0 {
                blocked.push(WithdrawalBlockedVault {
                    vault_id,
                    amount_sats: advertisement.amount_sats,
                    reason: "Vault has no withdrawable BTC".to_string(),
                });
                continue;
            }

            if advertisement.successor_depth > params.max_successor_depth {
                blocked.push(WithdrawalBlockedVault {
                    vault_id,
                    amount_sats: advertisement.amount_sats,
                    reason: format!(
                        "Vault successor depth {} exceeds maximum {}",
                        advertisement.successor_depth, params.max_successor_depth
                    ),
                });
                continue;
            }

            if !advertisement.routeable {
                blocked.push(WithdrawalBlockedVault {
                    vault_id,
                    amount_sats: advertisement.amount_sats,
                    reason: Self::advertisement_block_reason(&advertisement),
                });
                continue;
            }

            // dBTC Definition 7: verify UTXO liveness on Bitcoin before considering vault eligible.
            // The bearer's device must verify all 3 facts (token commitment + live UTXO + policy match).
            if let Some(mp) = mempool {
                let htlc_addr = &advertisement.htlc_address;
                if htlc_addr.is_empty() {
                    blocked.push(WithdrawalBlockedVault {
                        vault_id,
                        amount_sats: advertisement.amount_sats,
                        reason: "No HTLC address in vault advertisement".to_string(),
                    });
                    continue;
                }
                match mp.address_utxos(htlc_addr).await {
                    Ok(utxos) => {
                        if utxos.is_empty() {
                            blocked.push(WithdrawalBlockedVault {
                                vault_id,
                                amount_sats: advertisement.amount_sats,
                                reason: "UTXO not found on-chain (spent or unconfirmed)"
                                    .to_string(),
                            });
                            continue;
                        }
                        // Check burial depth if chain tip is known
                        if let Some(tip) = chain_tip {
                            let any_confirmed = utxos.iter().any(|u| u.confirmed);
                            if !any_confirmed {
                                blocked.push(WithdrawalBlockedVault {
                                    vault_id,
                                    amount_sats: advertisement.amount_sats,
                                    reason: "UTXO exists but unconfirmed".to_string(),
                                });
                                continue;
                            }
                            // Note: mempool.space address_utxos doesn't return block height per UTXO,
                            // so we can't compute exact burial depth here. The entry_txid-based depth
                            // check happens at execution time via tx_status(). The existence + confirmed
                            // check here is the pre-flight gate.
                            let _ = tip; // used for future depth verification
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "[withdraw.plan] UTXO liveness check failed for vault {}: {e}",
                            &vault_id[..vault_id.len().min(12)],
                        );
                        blocked.push(WithdrawalBlockedVault {
                            vault_id,
                            amount_sats: advertisement.amount_sats,
                            reason: format!("Bitcoin liveness check failed: {e}"),
                        });
                        continue;
                    }
                }
            }

            let storage_node_view = Self::build_storage_node_vault_routing_view_from_inventory(
                &advertisement.vault_id,
                &inventory,
            )?;
            if let Some(storage_node_view) = storage_node_view {
                if let Err(e) = self.ensure_vault_in_memory(&advertisement.vault_id).await {
                    blocked.push(WithdrawalBlockedVault {
                        vault_id: advertisement.vault_id.clone(),
                        amount_sats: advertisement.amount_sats,
                        reason: format!("execution artifacts unavailable: {e}"),
                    });
                    continue;
                }
                if let Some(reason) = Self::validate_storage_node_advertisement_against_view(
                    &advertisement,
                    &storage_node_view,
                ) {
                    blocked.push(WithdrawalBlockedVault {
                        vault_id: advertisement.vault_id.clone(),
                        amount_sats: advertisement.amount_sats,
                        reason,
                    });
                    continue;
                }
                if !storage_node_view.routeable {
                    blocked.push(WithdrawalBlockedVault {
                        vault_id: advertisement.vault_id.clone(),
                        amount_sats: advertisement.amount_sats,
                        reason: storage_node_view
                            .busy_reason
                            .unwrap_or_else(|| "Vault is not routeable".to_string()),
                    });
                    continue;
                }

                eligible.push(WithdrawableVault {
                    vault_id: advertisement.vault_id.clone(),
                    amount_sats: advertisement.amount_sats,
                    successor_depth: advertisement.successor_depth,
                });
                eligible_advertisements.push(advertisement);
                continue;
            }

            // Remote vault path: vault is on storage nodes, not in storage_node inventory.
            // Verify artifacts exist, then load into memory so withdrawal can proceed (dBTC §6.2).
            //
            // KNOWN LIMITATION (audit finding §3 — High):
            // This path treats storage-node-discovered vaults as executable by the bearer.
            // The dBTC paper (Property 5, §21.2-§21.3) requires that any bearer with
            // sufficient dBTC balance can redeem against any compatible live vault in the
            // grid without the original depositor's cooperation.
            //
            // In the current implementation, load_remote_vault_into_memory() constructs an
            // in-memory VaultOperation record from public ad data, but execution (pour_partial,
            // drain_tap) requires a locally-derived preimage. For vaults created on this device,
            // the preimage is derivable from manifold_seed + deposit_nonce. For vaults created
            // on OTHER devices, the bearer cannot derive the preimage without access to that
            // device's manifold_seed — so execution will fail even if planning succeeds.
            //
            // Until full bearer-derived witness derivation is implemented across all grid vaults
            // (regardless of origin device), storage-node-discovered vaults should only be
            // offered as eligible if they were created by the current device (i.e., their
            // deposit_nonce is resolvable to a preimage via the local manifold_seed).
            // Planning may still include remote vaults as aspirational liquidity, but callers
            // should understand that execution may fail for cross-device vaults.
            match Self::verify_remote_vault_artifacts(&advertisement).await {
                Ok(()) => {
                    if let Err(e) = self.load_remote_vault_into_memory(&advertisement).await {
                        blocked.push(WithdrawalBlockedVault {
                            vault_id: advertisement.vault_id.clone(),
                            amount_sats: advertisement.amount_sats,
                            reason: format!("remote vault load failed: {e}"),
                        });
                        continue;
                    }
                    eligible.push(WithdrawableVault {
                        vault_id: advertisement.vault_id.clone(),
                        amount_sats: advertisement.amount_sats,
                        successor_depth: advertisement.successor_depth,
                    });
                    eligible_advertisements.push(advertisement);
                }
                Err(e) => {
                    blocked.push(WithdrawalBlockedVault {
                        vault_id: advertisement.vault_id.clone(),
                        amount_sats: advertisement.amount_sats,
                        reason: format!("execution artifacts unavailable: {e}"),
                    });
                }
            }
        }

        // dBTC spec §11 Step 2: "Check available anchors (storage_node device storage)."
        // storage_node creator mirrors supplement storage-node discovery; transfer state
        // must not synthesize additional vault authority.
        // Any storage_nodely cached vault NOT already seen in the advertisement loop must
        // still be considered.
        let seen_vault_ids: HashSet<String> = eligible
            .iter()
            .map(|v| v.vault_id.clone())
            .chain(blocked.iter().map(|v| v.vault_id.clone()))
            .collect();

        for storage_node_vault_id in &inventory.storage_node_vault_ids {
            if seen_vault_ids.contains(storage_node_vault_id) {
                continue;
            }
            let storage_node_view =
                match Self::build_storage_node_vault_routing_view_from_inventory(
                    storage_node_vault_id,
                    &inventory,
                )? {
                    Some(v) => v,
                    None => continue,
                };
            if storage_node_view.amount_sats == 0 {
                blocked.push(WithdrawalBlockedVault {
                    vault_id: storage_node_vault_id.clone(),
                    amount_sats: 0,
                    reason: "storage_node vault has no withdrawable BTC".to_string(),
                });
                continue;
            }
            if storage_node_view.successor_depth > params.max_successor_depth {
                blocked.push(WithdrawalBlockedVault {
                    vault_id: storage_node_vault_id.clone(),
                    amount_sats: storage_node_view.amount_sats,
                    reason: format!(
                        "Vault successor depth {} exceeds maximum {}",
                        storage_node_view.successor_depth, params.max_successor_depth
                    ),
                });
                continue;
            }
            if !storage_node_view.routeable {
                blocked.push(WithdrawalBlockedVault {
                    vault_id: storage_node_vault_id.clone(),
                    amount_sats: storage_node_view.amount_sats,
                    reason: storage_node_view
                        .busy_reason
                        .unwrap_or_else(|| "Vault is not routeable".to_string()),
                });
                continue;
            }
            if let Err(e) = self.ensure_vault_in_memory(storage_node_vault_id).await {
                blocked.push(WithdrawalBlockedVault {
                    vault_id: storage_node_vault_id.clone(),
                    amount_sats: storage_node_view.amount_sats,
                    reason: format!("storage_node vault execution artifacts unavailable: {e}"),
                });
                continue;
            }
            // dBTC Definition 7: verify UTXO liveness for storage_node vaults too.
            if let Some(mp) = mempool {
                let htlc_addr = storage_node_view.htlc_address.as_deref().unwrap_or("");
                if htlc_addr.is_empty() {
                    blocked.push(WithdrawalBlockedVault {
                        vault_id: storage_node_vault_id.clone(),
                        amount_sats: storage_node_view.amount_sats,
                        reason: "No HTLC address for storage_node vault".to_string(),
                    });
                    continue;
                }
                match mp.address_utxos(htlc_addr).await {
                    Ok(utxos) if utxos.is_empty() => {
                        blocked.push(WithdrawalBlockedVault {
                            vault_id: storage_node_vault_id.clone(),
                            amount_sats: storage_node_view.amount_sats,
                            reason: "UTXO not found on-chain (spent or unconfirmed)".to_string(),
                        });
                        continue;
                    }
                    Ok(utxos) => {
                        if let Some(_tip) = chain_tip {
                            let any_confirmed = utxos.iter().any(|u| u.confirmed);
                            if !any_confirmed {
                                blocked.push(WithdrawalBlockedVault {
                                    vault_id: storage_node_vault_id.clone(),
                                    amount_sats: storage_node_view.amount_sats,
                                    reason: "UTXO exists but unconfirmed".to_string(),
                                });
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "[withdraw.plan] UTXO liveness check failed for storage_node vault {}: {e}",
                            &storage_node_vault_id[..storage_node_vault_id.len().min(12)],
                        );
                        blocked.push(WithdrawalBlockedVault {
                            vault_id: storage_node_vault_id.clone(),
                            amount_sats: storage_node_view.amount_sats,
                            reason: format!("Bitcoin liveness check failed: {e}"),
                        });
                        continue;
                    }
                }
            }

            log::info!(
                "[withdraw.plan] storage_node-anchor vault eligible: vault={} amount={}sats depth={}",
                &storage_node_vault_id[..storage_node_vault_id.len().min(12)],
                storage_node_view.amount_sats,
                storage_node_view.successor_depth,
            );
            // Build a synthetic advertisement so downstream route-commitment
            // canonicalization includes this vault's data.
            let synthetic_ad = Self::build_vault_advertisement(
                &storage_node_view,
                &[0u8; 32], // controller device_id unknown for received vaults
            );
            eligible.push(WithdrawableVault {
                vault_id: storage_node_vault_id.clone(),
                amount_sats: storage_node_view.amount_sats,
                successor_depth: storage_node_view.successor_depth,
            });
            eligible_advertisements.push(synthetic_ad);
        }

        eligible.sort_by(|a, b| {
            b.amount_sats
                .cmp(&a.amount_sats)
                .then(a.vault_id.cmp(&b.vault_id))
        });
        eligible_advertisements.sort_by(|a, b| a.vault_id.cmp(&b.vault_id));

        Ok(WithdrawalSelectorInput {
            eligible,
            blocked,
            eligible_advertisements,
        })
    }

    pub(crate) async fn prepare_withdrawal_plan(
        &self,
        requested_gross_sats: u64,
        destination_address: &str,
        planner_device_id: &[u8; 32],
    ) -> Result<WithdrawalPlan, DsmError> {
        if requested_gross_sats == 0 {
            return Err(DsmError::invalid_operation(
                "Withdrawal amount must be greater than 0",
            ));
        }
        // The user's input is the GROSS amount — the total dBTC to burn.
        // Bitcoin network fee comes out of this amount: net = gross - fee.
        // This matches user expectation: "I have X dBTC, withdraw it all."
        let params = DbtcParams::resolve();
        let estimated_fee = estimated_full_withdrawal_fee_sats();
        if requested_gross_sats <= estimated_fee {
            return Err(DsmError::invalid_operation(format!(
                "Withdrawal amount ({} sats) must exceed estimated Bitcoin network fee ({} sats)",
                requested_gross_sats, estimated_fee,
            )));
        }
        let requested_net_sats = requested_gross_sats.saturating_sub(estimated_fee);
        if requested_net_sats < params.min_exit_sats {
            return Err(DsmError::invalid_operation(format!(
                "Withdrawal below minimum after fee: {} sats net ({} gross - {} fee), minimum is {} sats \
                 (dust floor {} + estimated sweep fee {})",
                requested_net_sats,
                requested_gross_sats,
                estimated_fee,
                params.min_exit_sats,
                params.dust_floor_sats,
                params.estimated_sweep_fee_sats,
            )));
        }
        if destination_address.trim().is_empty() {
            return Err(DsmError::invalid_operation(
                "Destination address is required",
            ));
        }

        // dBTC §8 recovery: refresh all local vault advertisements before planning.
        // This catches ads that failed to publish during deposit (draw_tap/bitcoin.deposit.complete
        // silently swallow publish errors) or successor vaults still awaiting entry_txid.
        // Without this, the planner sees stale/empty ads on storage nodes and blocks vaults
        // that are actually live (e.g., "No HTLC address in vault advertisement").
        if let Err(e) = self
            .refresh_storage_node_vault_advertisements(planner_device_id)
            .await
        {
            log::warn!("[withdraw.plan] advertisement refresh failed: {e}");
        }

        // Query bearer's dBTC balance from canonical archived state for early warning.
        // Fallback to the validated projection row only if this device has not yet archived
        // a canonical state snapshot locally.
        let device_id_str = crate::util::text_id::encode_base32_crockford(planner_device_id);
        let available_dbtc_sats = Self::canonical_archived_dbtc_balance(planner_device_id)
            .or_else(|| {
                match crate::storage::client_db::get_balance_projection(
                    &device_id_str,
                    DBTC_TOKEN_ID,
                ) {
                    Ok(Some(record)) => Some(record.available),
                    Ok(None) => None,
                    Err(e) => {
                        log::error!("[withdraw.plan] failed to read fallback dBTC projection: {e}");
                        None
                    }
                }
            })
            .unwrap_or(0);

        // dBTC Definition 7: construct mempool client for UTXO liveness verification.
        // The bearer's device must verify all 3 facts before planning a withdrawal.
        // If the chain tip is unreachable, degrade gracefully — skip UTXO pre-check
        // and let execution-time broadcast catch stale UTXOs.
        #[cfg(not(test))]
        let (mempool_client, chain_tip) = {
            let network = crate::sdk::runtime_config::RuntimeConfig::get_bitcoin_network();
            match crate::handlers::mempool_api::MempoolClient::from_config_for_network(network) {
                Ok(mp) => match mp.chain_tip_height().await {
                    Ok(tip) => (Some(mp), Some(tip)),
                    Err(e) => {
                        log::warn!("[withdraw.plan] mempool chain tip unreachable, skipping UTXO liveness pre-check: {e}");
                        (None, None)
                    }
                },
                Err(e) => {
                    log::warn!("[withdraw.plan] mempool client init failed, skipping UTXO liveness pre-check: {e}");
                    (None, None)
                }
            }
        };
        #[cfg(test)]
        let (mempool_client, chain_tip): (
            Option<crate::handlers::mempool_api::MempoolClient>,
            Option<u64>,
        ) = (None, None);
        let selector_input = self
            .build_global_selector_input(mempool_client.as_ref(), chain_tip)
            .await?;
        let WithdrawalSelectorInput {
            eligible,
            blocked: mut blocked_vaults,
            eligible_advertisements,
        } = selector_input;
        blocked_vaults.sort_by(|a, b| a.vault_id.cmp(&b.vault_id).then(a.reason.cmp(&b.reason)));
        let policy_commit = Self::dbtc_policy_commit();

        log::info!(
            "[withdraw.plan] requested={}sats eligible={} blocked={} advertisements={}",
            requested_net_sats,
            eligible.len(),
            blocked_vaults.len(),
            eligible_advertisements.len(),
        );
        for v in &eligible {
            log::info!(
                "[withdraw.plan]   eligible: vault={} amount={}sats depth={}",
                &v.vault_id[..v.vault_id.len().min(12)],
                v.amount_sats,
                v.successor_depth,
            );
        }
        for v in &blocked_vaults {
            log::warn!(
                "[withdraw.plan]   blocked: vault={} amount={}sats reason={}",
                &v.vault_id[..v.vault_id.len().min(12)],
                v.amount_sats,
                v.reason,
            );
        }

        let Some(candidate) = Self::select_withdrawal_route(&eligible, requested_net_sats) else {
            log::warn!(
                "[withdraw.plan] no executable route found — eligible={} requested={}sats",
                eligible.len(),
                requested_net_sats,
            );
            return Ok(WithdrawalPlan {
                plan_id: String::new(),
                plan_class: "unavailable".to_string(),
                requested_net_sats,
                planned_net_sats: 0,
                total_gross_exit_sats: 0,
                total_fee_sats: 0,
                shortfall_sats: requested_net_sats,
                legs: Vec::new(),
                blocked_vaults,
                policy_commit,
                available_dbtc_sats,
            });
        };

        // Fees come out of the delivered amount — they are not a shortfall.
        // Shortfall only reflects genuinely unroutable liquidity.
        let shortfall_sats = if candidate.total_gross_exit_sats >= requested_net_sats {
            0
        } else {
            requested_net_sats.saturating_sub(candidate.total_gross_exit_sats)
        };
        let mut plan_class = Self::classify_withdrawal_plan(&candidate.legs).to_string();
        let plan_id = Self::compute_withdrawal_plan_id(
            requested_net_sats,
            destination_address,
            &candidate,
            shortfall_sats,
        );
        // Gate on GROSS exit amount, not NET. Handlers burn the gross (net + fee)
        // because Bitcoin tx fees are lost BTC backing that must be matched by dBTC burn.
        if available_dbtc_sats < candidate.total_gross_exit_sats && plan_class != "unavailable" {
            plan_class = "insufficient_dbtc".to_string();
        }
        let plan = WithdrawalPlan {
            plan_id,
            plan_class,
            requested_net_sats,
            planned_net_sats: candidate.planned_net_sats,
            total_gross_exit_sats: candidate.total_gross_exit_sats,
            total_fee_sats: candidate.total_fee_sats,
            shortfall_sats,
            legs: candidate.legs,
            blocked_vaults,
            policy_commit,
            available_dbtc_sats,
        };

        Ok(plan)
    }

    pub async fn plan_withdrawal(
        &self,
        requested_gross_sats: u64,
        destination_address: &str,
        planner_device_id: &[u8; 32],
    ) -> Result<WithdrawalPlan, DsmError> {
        self.prepare_withdrawal_plan(requested_gross_sats, destination_address, planner_device_id)
            .await
    }

    /// Fetch vault execution data from storage nodes by vault_id.
    ///
    /// This is the proper path — unilateral action against storage nodes.
    /// Anyone holding dBTC tokens can call this. No local vault record needed.
    /// Storage nodes have everything: htlc_script, htlc_address, deposit_nonce.
    /// The tokens are the key.
    pub async fn fetch_vault_execution_data(
        &self,
        vault_id: &str,
    ) -> Result<VaultExecutionData, DsmError> {
        let ad_key = Self::vault_advertisement_key(vault_id);
        let ad_bytes = Self::storage_get_bytes(&ad_key).await.map_err(|e| {
            DsmError::storage(
                format!("fetch vault advertisement for {vault_id}: {e}"),
                None::<std::io::Error>,
            )
        })?;
        let ad = generated::DbtcVaultAdvertisementV1::decode(ad_bytes.as_slice()).map_err(|e| {
            DsmError::serialization_error(
                "DbtcVaultAdvertisementV1",
                "decode",
                Some(vault_id),
                Some(e),
            )
        })?;

        if ad.htlc_address.is_empty() {
            return Err(DsmError::invalid_operation(
                "vault advertisement missing htlc_address",
            ));
        }
        if ad.redeem_params.is_empty() {
            return Err(DsmError::invalid_operation(
                "vault advertisement missing redeem_params",
            ));
        }
        if ad.deposit_nonce.len() != 32 {
            return Err(DsmError::invalid_operation(
                "vault advertisement missing 32-byte deposit_nonce",
            ));
        }

        let params =
            generated::DbtcRedeemParams::decode(ad.redeem_params.as_slice()).map_err(|e| {
                DsmError::serialization_error("DbtcRedeemParams", "decode", Some(vault_id), Some(e))
            })?;

        if params.htlc_script.is_empty() {
            return Err(DsmError::invalid_operation(
                "vault redeem_params missing htlc_script",
            ));
        }
        let mut hash_lock = [0u8; 32];
        if params.hash_lock.len() == 32 {
            hash_lock.copy_from_slice(&params.hash_lock);
        } else {
            return Err(DsmError::invalid_operation(
                "vault redeem_params missing 32-byte hash_lock",
            ));
        }

        let mut deposit_nonce = [0u8; 32];
        deposit_nonce.copy_from_slice(&ad.deposit_nonce);

        let mut policy_commit = [0u8; 32];
        if ad.policy_commit.len() == 32 {
            policy_commit.copy_from_slice(&ad.policy_commit);
        } else {
            return Err(DsmError::invalid_operation(
                "vault advertisement missing 32-byte policy_commit",
            ));
        }

        let vault_content_hash = {
            let digest = dsm::crypto::blake3::domain_hash("DSM/vault-ad", &ad_bytes);
            let mut h = [0u8; 32];
            h.copy_from_slice(digest.as_bytes());
            h
        };

        Ok(VaultExecutionData {
            vault_id: vault_id.to_string(),
            amount_sats: ad.amount_sats,
            successor_depth: ad.successor_depth,
            htlc_script: params.htlc_script,
            htlc_address: ad.htlc_address,
            hash_lock,
            deposit_nonce,
            policy_commit,
            vault_content_hash,
        })
    }

    /// Derive preimage from a deposit_nonce + manifold_seed.
    /// Public interface for execution paths that get deposit_nonce from
    /// storage node advertisements (not local vault records).
    pub fn derive_preimage_from_deposit_nonce(
        deposit_nonce: &[u8; 32],
        policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, DsmError> {
        let manifold_seed = crate::storage::client_db::get_or_create_manifold_seed(policy_commit)
            .map_err(|e| {
            DsmError::storage(format!("manifold_seed: {e}"), None::<std::io::Error>)
        })?;
        let eta = Self::derive_bearer_eta(&manifold_seed, deposit_nonce);
        Ok(Self::derive_preimage_from_eta(&eta))
    }

    fn busy_vault_reason(
        vault_records: &[crate::storage::client_db::PersistedVaultRecord],
        child_records: &[crate::storage::client_db::PersistedVaultRecord],
    ) -> Option<String> {
        let busy_exit = vault_records.iter().find(|record| {
            if record.direction != "dbtc_to_btc" {
                return false;
            }
            Self::is_busy_withdrawal_state(&record.vault_state)
        });
        if let Some(record) = busy_exit {
            return Some(format!("Exit already in progress ({})", record.vault_state));
        }

        let busy_child = child_records.iter().find(|record| {
            record.is_fractional_successor && Self::is_busy_withdrawal_state(&record.vault_state)
        });
        if let Some(record) = busy_child {
            return Some(format!(
                "Successor vault still pending confirmation ({})",
                record.vault_state
            ));
        }

        None
    }

    fn is_busy_withdrawal_state(state: &str) -> bool {
        matches!(
            state.trim().to_ascii_lowercase().as_str(),
            "initiated" | "awaiting_confirmation" | "claimable" | "sweeppending" | "burnpending"
        )
    }

    fn select_withdrawal_route(
        vaults: &[WithdrawableVault],
        requested_net_sats: u64,
    ) -> Option<WithdrawalRouteCandidate> {
        let params = DbtcParams::resolve();
        let full_fee = estimated_full_withdrawal_fee_sats();
        let partial_fee = estimated_partial_withdrawal_fee_sats();
        let min_remainder = params.min_vault_balance_sats.max(params.dust_floor_sats);
        let min_partial_net = params.min_exit_sats.saturating_sub(partial_fee);
        let min_full_gross_sats = params.min_exit_sats;

        let mut exact_candidates = Vec::new();
        let mut lower_candidates = Vec::new();

        for partial_index in 0..=vaults.len() {
            let partial_index = if partial_index == vaults.len() {
                None
            } else {
                Some(partial_index)
            };
            let mut selected_fulls = Vec::new();
            Self::collect_withdrawal_candidates(
                vaults,
                partial_index,
                0,
                &mut selected_fulls,
                requested_net_sats,
                min_full_gross_sats,
                full_fee,
                partial_fee,
                min_partial_net,
                min_remainder,
                params.max_successor_depth,
                &mut exact_candidates,
                &mut lower_candidates,
            );
        }

        exact_candidates
            .into_iter()
            .min_by(Self::compare_exact_candidates)
            .or_else(|| {
                lower_candidates
                    .into_iter()
                    .min_by(Self::compare_lower_candidates)
            })
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_withdrawal_candidates(
        vaults: &[WithdrawableVault],
        partial_index: Option<usize>,
        start_index: usize,
        selected_fulls: &mut Vec<usize>,
        requested_net_sats: u64,
        min_full_gross_sats: u64,
        full_fee: u64,
        partial_fee: u64,
        min_partial_net: u64,
        min_remainder: u64,
        max_successor_depth: u32,
        exact_candidates: &mut Vec<WithdrawalRouteCandidate>,
        lower_candidates: &mut Vec<WithdrawalRouteCandidate>,
    ) {
        let candidate_without_partial = Self::build_full_only_candidate(vaults, selected_fulls);
        if let Some(candidate) = candidate_without_partial {
            if candidate.planned_net_sats == requested_net_sats {
                exact_candidates.push(candidate.clone());
            } else if candidate.planned_net_sats > 0
                && candidate.planned_net_sats < requested_net_sats
            {
                lower_candidates.push(candidate.clone());
            }
        }

        if let Some(partial_idx) = partial_index {
            if let Some(candidate) = Self::build_partial_candidate(
                vaults,
                selected_fulls,
                partial_idx,
                requested_net_sats,
                partial_fee,
                min_partial_net,
                min_remainder,
                max_successor_depth,
            ) {
                if candidate.planned_net_sats == requested_net_sats {
                    exact_candidates.push(candidate);
                } else if candidate.planned_net_sats > 0
                    && candidate.planned_net_sats < requested_net_sats
                {
                    lower_candidates.push(candidate);
                }
            }
        }

        for next_index in start_index..vaults.len() {
            if Some(next_index) == partial_index {
                continue;
            }
            let vault = &vaults[next_index];
            if vault.amount_sats < min_full_gross_sats || vault.amount_sats <= full_fee {
                continue;
            }
            let full_net = vault.amount_sats.saturating_sub(full_fee);
            let current_net = Self::selected_full_net(vaults, selected_fulls);
            if current_net.saturating_add(full_net) > requested_net_sats {
                continue;
            }
            selected_fulls.push(next_index);
            Self::collect_withdrawal_candidates(
                vaults,
                partial_index,
                next_index + 1,
                selected_fulls,
                requested_net_sats,
                min_full_gross_sats,
                full_fee,
                partial_fee,
                min_partial_net,
                min_remainder,
                max_successor_depth,
                exact_candidates,
                lower_candidates,
            );
            selected_fulls.pop();
        }
    }

    fn build_full_only_candidate(
        vaults: &[WithdrawableVault],
        selected_fulls: &[usize],
    ) -> Option<WithdrawalRouteCandidate> {
        if selected_fulls.is_empty() {
            return None;
        }
        let full_fee = estimated_full_withdrawal_fee_sats();
        let mut legs = Vec::with_capacity(selected_fulls.len());
        let mut planned_net_sats = 0u64;
        let mut total_gross_exit_sats = 0u64;
        let mut total_fee_sats = 0u64;

        for index in selected_fulls {
            let vault = &vaults[*index];
            let estimated_net_sats = vault.amount_sats.checked_sub(full_fee)?;
            legs.push(WithdrawalPlanLeg {
                vault_id: vault.vault_id.clone(),
                kind: WithdrawalLegKind::Full,
                source_amount_sats: vault.amount_sats,
                gross_exit_sats: vault.amount_sats,
                estimated_fee_sats: full_fee,
                estimated_net_sats,
                remainder_sats: 0,
                successor_depth_after: vault.successor_depth,
            });
            planned_net_sats = planned_net_sats.saturating_add(estimated_net_sats);
            total_gross_exit_sats = total_gross_exit_sats.saturating_add(vault.amount_sats);
            total_fee_sats = total_fee_sats.saturating_add(full_fee);
        }

        Some(WithdrawalRouteCandidate {
            legs,
            planned_net_sats,
            total_gross_exit_sats,
            total_fee_sats,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_partial_candidate(
        vaults: &[WithdrawableVault],
        selected_fulls: &[usize],
        partial_index: usize,
        requested_net_sats: u64,
        partial_fee: u64,
        min_partial_net: u64,
        min_remainder: u64,
        max_successor_depth: u32,
    ) -> Option<WithdrawalRouteCandidate> {
        let mut candidate = Self::build_full_only_candidate(vaults, selected_fulls).unwrap_or(
            WithdrawalRouteCandidate {
                legs: Vec::new(),
                planned_net_sats: 0,
                total_gross_exit_sats: 0,
                total_fee_sats: 0,
            },
        );
        let residual_target = requested_net_sats.saturating_sub(candidate.planned_net_sats);
        if residual_target == 0 {
            return None;
        }

        let vault = &vaults[partial_index];
        let next_depth = vault.successor_depth.saturating_add(1);
        if next_depth > max_successor_depth {
            return None;
        }
        if vault.amount_sats <= min_remainder {
            return None;
        }

        let max_gross_exit_sats = vault.amount_sats.saturating_sub(min_remainder);
        if max_gross_exit_sats == 0 {
            return None;
        }
        let max_partial_net = max_gross_exit_sats.checked_sub(partial_fee)?;
        if max_partial_net == 0 || max_partial_net < min_partial_net {
            return None;
        }

        let partial_net_sats = residual_target.min(max_partial_net);
        if partial_net_sats < min_partial_net {
            return None;
        }

        let gross_exit_sats = partial_net_sats.checked_add(partial_fee)?;
        if gross_exit_sats >= vault.amount_sats {
            return None;
        }
        let remainder_sats = vault.amount_sats.checked_sub(gross_exit_sats)?;
        if remainder_sats < min_remainder {
            return None;
        }

        candidate.legs.push(WithdrawalPlanLeg {
            vault_id: vault.vault_id.clone(),
            kind: WithdrawalLegKind::Partial,
            source_amount_sats: vault.amount_sats,
            gross_exit_sats,
            estimated_fee_sats: partial_fee,
            estimated_net_sats: partial_net_sats,
            remainder_sats,
            successor_depth_after: next_depth,
        });
        candidate.planned_net_sats = candidate.planned_net_sats.saturating_add(partial_net_sats);
        candidate.total_gross_exit_sats = candidate
            .total_gross_exit_sats
            .saturating_add(gross_exit_sats);
        candidate.total_fee_sats = candidate.total_fee_sats.saturating_add(partial_fee);
        Some(candidate)
    }

    fn selected_full_net(vaults: &[WithdrawableVault], selected_fulls: &[usize]) -> u64 {
        let full_fee = estimated_full_withdrawal_fee_sats();
        selected_fulls.iter().fold(0u64, |acc, index| {
            acc.saturating_add(vaults[*index].amount_sats.saturating_sub(full_fee))
        })
    }

    fn compare_exact_candidates(
        left: &WithdrawalRouteCandidate,
        right: &WithdrawalRouteCandidate,
    ) -> std::cmp::Ordering {
        left.legs
            .len()
            .cmp(&right.legs.len())
            .then(left.total_fee_sats.cmp(&right.total_fee_sats))
            .then(Self::route_signature(&left.legs).cmp(&Self::route_signature(&right.legs)))
    }

    fn compare_lower_candidates(
        left: &WithdrawalRouteCandidate,
        right: &WithdrawalRouteCandidate,
    ) -> std::cmp::Ordering {
        right
            .planned_net_sats
            .cmp(&left.planned_net_sats)
            .then(left.legs.len().cmp(&right.legs.len()))
            .then(left.total_fee_sats.cmp(&right.total_fee_sats))
            .then(Self::route_signature(&left.legs).cmp(&Self::route_signature(&right.legs)))
    }

    fn route_signature(legs: &[WithdrawalPlanLeg]) -> String {
        legs.iter()
            .map(|leg| {
                format!(
                    "{}:{}:{}",
                    leg.vault_id,
                    leg.kind.as_str(),
                    leg.gross_exit_sats
                )
            })
            .collect::<Vec<_>>()
            .join("|")
    }

    fn classify_withdrawal_plan(legs: &[WithdrawalPlanLeg]) -> &'static str {
        match (
            legs.len(),
            legs.iter().all(|leg| leg.kind == WithdrawalLegKind::Full),
        ) {
            (1, true) => "single_full_sweep",
            (1, false) => "single_partial_sweep",
            (_, true) => "multiple_full_sweeps",
            _ => "multiple_full_plus_partial",
        }
    }

    fn compute_withdrawal_plan_id(
        requested_net_sats: u64,
        destination_address: &str,
        candidate: &WithdrawalRouteCandidate,
        shortfall_sats: u64,
    ) -> String {
        let mut hasher = dsm_domain_hasher("DSM/dbtc-withdrawal-plan");
        hasher.update(&requested_net_sats.to_le_bytes());
        hasher.update(destination_address.as_bytes());
        hasher.update(&candidate.planned_net_sats.to_le_bytes());
        hasher.update(&candidate.total_gross_exit_sats.to_le_bytes());
        hasher.update(&candidate.total_fee_sats.to_le_bytes());
        hasher.update(&shortfall_sats.to_le_bytes());
        for leg in &candidate.legs {
            hasher.update(leg.vault_id.as_bytes());
            hasher.update(leg.kind.as_str().as_bytes());
            hasher.update(&leg.source_amount_sats.to_le_bytes());
            hasher.update(&leg.gross_exit_sats.to_le_bytes());
            hasher.update(&leg.estimated_fee_sats.to_le_bytes());
            hasher.update(&leg.estimated_net_sats.to_le_bytes());
            hasher.update(&leg.remainder_sats.to_le_bytes());
            hasher.update(&leg.successor_depth_after.to_le_bytes());
        }
        let digest = hasher.finalize();
        let mut word = [0u8; 8];
        word.copy_from_slice(&digest.as_bytes()[0..8]);
        format!("withdraw-{}", u64::from_le_bytes(word))
    }

    /// List all vault op IDs
    pub async fn list_vault_ops(&self) -> Vec<String> {
        let ops = self.pending_ops.read().await;
        ops.keys().cloned().collect()
    }

    /// List all vault ops with their records (id, record pairs).
    pub async fn list_vault_records(&self) -> Vec<(String, VaultOperation)> {
        let ops = self.pending_ops.read().await;
        ops.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// Verify a Bitcoin payment independently (standalone SPV check).
    pub fn verify_bitcoin_payment(
        txid: &[u8; 32],
        spv_proof_bytes: &[u8],
        block_header: &[u8; 80],
    ) -> Result<bool, DsmError> {
        let proof = SpvProof::from_bytes(spv_proof_bytes)?;
        Ok(dsm::bitcoin::spv::verify_tx_in_block(
            txid,
            block_header,
            &proof,
        ))
    }

    /// Generate a Bitcoin dual-hashlock HTLC address for a deposit.
    ///
    /// Per main.tex Definition 7.1: dual-hashlock script with fulfill and refund paths.
    pub fn generate_htlc_address(
        fulfill_hash: &[u8; 32],
        refund_hash: &[u8; 32],
        claimer_pubkey: &[u8],
        refund_pubkey: &[u8],
        network: BitcoinNetwork,
    ) -> Result<(Vec<u8>, String), DsmError> {
        let script = build_htlc_script(fulfill_hash, refund_hash, claimer_pubkey, refund_pubkey)?;
        let address = htlc_p2wsh_address(&script, network)?;
        Ok((script, address))
    }

    /// Create the `TokenOperation::Lock` used to reserve dBTC for an exit flow.
    pub fn seal_tap(amount_sats: u64, vault_op_id: &str) -> TokenOperation {
        TokenOperation::Lock {
            token_id: DBTC_TOKEN_ID.to_string(),
            amount: amount_sats,
            purpose: format!("deposit:{vault_op_id}").into_bytes(),
        }
    }

    // --- Internal helpers ---

    /// Derive the HTLC preimage deterministically from η.
    /// s = BLAKE3("DSM/dbtc-preimage\0" || η)
    fn derive_preimage_from_eta(eta: &[u8; 32]) -> Vec<u8> {
        dsm::crypto::blake3::domain_hash_bytes("DSM/dbtc-preimage", eta).to_vec()
    }

    /// Derive bearer η from manifold_seed + deposit_nonce.
    /// η = BLAKE3("DSM/dbtc-bearer-eta\0" || manifold_seed || deposit_nonce)
    /// Any bearer holding manifold_seed can compute η for any vault whose deposit_nonce
    /// they discover from storage node advertisements.
    fn derive_bearer_eta(manifold_seed: &[u8; 32], deposit_nonce: &[u8; 32]) -> [u8; 32] {
        let mut hasher = dsm_domain_hasher("DSM/dbtc-bearer-eta");
        hasher.update(manifold_seed);
        hasher.update(deposit_nonce);
        *hasher.finalize().as_bytes()
    }

    /// Derive preimage from a VaultOperation's deposit_nonce + manifold_seed.
    /// Single derivation path: deposit_nonce → η → preimage.
    pub(crate) fn derive_preimage(record: &VaultOperation) -> Result<Vec<u8>, DsmError> {
        let deposit_nonce = record.deposit_nonce.ok_or_else(|| {
            DsmError::invalid_operation("No deposit_nonce — cannot derive preimage")
        })?;
        let policy_commit = Self::dbtc_policy_commit();
        let manifold_seed = crate::storage::client_db::get_or_create_manifold_seed(&policy_commit)
            .map_err(|e| {
                DsmError::storage(format!("manifold_seed: {e}"), None::<std::io::Error>)
            })?;
        let eta = Self::derive_bearer_eta(&manifold_seed, &deposit_nonce);
        Ok(Self::derive_preimage_from_eta(&eta))
    }

    /// Generate a deterministic vault op ID from hash_lock and vault_id
    pub(crate) fn generate_vault_op_id(hash_lock: &[u8; 32], vault_id: &str) -> String {
        let mut hasher = dsm_domain_hasher("DSM/btc-deposit-id");
        hasher.update(hash_lock);
        hasher.update(vault_id.as_bytes());
        let h = hasher.finalize();
        let mut w = [0u8; 8];
        w.copy_from_slice(&h.as_bytes()[0..8]);
        let n = u64::from_le_bytes(w);
        format!("deposit-{n}")
    }

    /// Encode dBTC content for DLV storage.
    ///
    /// Format: `amount_sats (8 bytes LE) || "dBTC" (4 bytes)`
    fn encode_dbtc_content(amount_sats: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&amount_sats.to_le_bytes());
        out.extend_from_slice(DBTC_TOKEN_ID.as_bytes());
        out
    }

    /// Decode dBTC content from DLV storage.
    pub fn decode_dbtc_content(content: &[u8]) -> Result<u64, DsmError> {
        if content.len() < 8 {
            return Err(DsmError::invalid_operation("dBTC content too short"));
        }
        let amount = u64::from_le_bytes(
            content[..8]
                .try_into()
                .map_err(|_| DsmError::invalid_operation("Invalid dBTC content"))?,
        );
        Ok(amount)
    }

    /// Create an external commitment for a deposit phase
    fn create_deposit_commitment(
        hash_lock: &[u8; 32],
        vault_id: &str,
        direction: &str,
        amount_sats: u64,
        reference_state: &State,
    ) -> [u8; 32] {
        let source_id = external_source_id(BITCOIN_SOURCE);

        // Evidence: hash_lock || vault_id || direction || amount || state_number
        let mut evidence = Vec::new();
        evidence.extend_from_slice(hash_lock);
        evidence.extend_from_slice(vault_id.as_bytes());
        evidence.extend_from_slice(direction.as_bytes());
        evidence.extend_from_slice(&amount_sats.to_le_bytes());
        evidence.extend_from_slice(&(reference_state.hash[0] as u64).to_le_bytes());
        let evidence_hash = external_evidence_hash(&evidence);

        create_external_commitment(hash_lock, &source_id, &evidence_hash)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bilateral transport helpers — called by the transport layer (BLE / online).
// These encapsulate all dBTC protocol logic so that transport code stays
// opaque: it passes token_id + bytes, and the SDK decides what to do.
// ─────────────────────────────────────────────────────────────────────────────

/// Role passed by the transport layer after a bilateral commit so that the SDK
/// can apply the correct vault state transition.  Transport code never branches
#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::client_db::PersistedVaultRecord;
    use dsm::types::proto as generated;
    use dsm::vault::{DLVManager, FulfillmentMechanism, LimboVault, VaultState};
    use prost::Message;
    use serial_test::serial;
    use std::sync::Arc;

    fn withdrawable_vault(
        vault_id: &str,
        amount_sats: u64,
        successor_depth: u32,
    ) -> WithdrawableVault {
        WithdrawableVault {
            vault_id: vault_id.to_string(),
            amount_sats,
            successor_depth,
        }
    }

    fn persisted_deposit_record(
        direction: &str,
        deposit_state: &str,
        vault_id: Option<&str>,
        parent_vault_id: Option<&str>,
        is_fractional_successor: bool,
    ) -> PersistedVaultRecord {
        PersistedVaultRecord {
            vault_op_id: format!("deposit-{direction}-{deposit_state}"),
            direction: direction.to_string(),
            vault_state: deposit_state.to_string(),
            hash_lock: Vec::new(),
            vault_id: vault_id.map(str::to_string),
            btc_amount_sats: 0,
            btc_pubkey: Vec::new(),
            htlc_script: None,
            htlc_address: None,
            external_commitment: None,
            refund_iterations: 0,
            created_at_state: 0,
            entry_header: None,
            parent_vault_id: parent_vault_id.map(str::to_string),
            successor_depth: 0,
            is_fractional_successor,
            refund_hash_lock: Vec::new(),
            destination_address: None,
            funding_txid: None,
            exit_amount_sats: 0,
            exit_header: None,
            exit_confirm_depth: 0,
            entry_txid: None,
            deposit_nonce: None,
        }
    }

    fn init_withdrawal_test_db() {
        unsafe {
            std::env::set_var("DSM_SDK_TEST_MODE", "1");
        }
        crate::storage::client_db::reset_database_for_tests();
        BitcoinTapSdk::reset_dbtc_storage_test_state();
        crate::storage::client_db::init_database()
            .unwrap_or_else(|e| panic!("init db failed: {e}"));
    }

    /// Derive a deterministic 32-byte test vault_id from a human-readable label.
    /// Test labels stay descriptive in source while the on-disk + on-wire id is
    /// the strict 32-byte form `LimboVaultProto.id` requires.
    fn vid_from_label(label: &str) -> [u8; 32] {
        dsm::crypto::blake3::domain_hash_bytes("DSM/dbtc-test-vault", label.as_bytes())
    }

    fn put_active_vault(vault_id: [u8; 32], amount_sats: u64) {
        let vid_b32 = crate::util::text_id::encode_base32_crockford(&vault_id);
        let proto = generated::LimboVaultProto {
            id: vault_id.to_vec(),
            fulfillment_condition: Some(generated::FulfillmentMechanism {
                kind: Some(generated::fulfillment_mechanism::Kind::BitcoinHtlc(
                    generated::BitcoinHtlc {
                        hash_lock: vec![0x11; 32],
                        refund_hash_lock: vec![0x22; 32],
                        refund_iterations: 42,
                        bitcoin_pubkey: vec![0x03; 33],
                        expected_btc_amount_sats: amount_sats,
                        network: 0,
                        min_confirmations: 1,
                    },
                )),
            }),
            ..Default::default()
        }
        .encode_to_vec();

        crate::storage::client_db::put_vault(&vid_b32, &proto, "active", &[0x44; 80], amount_sats)
            .unwrap_or_else(|e| panic!("store vault failed: {e}"));
    }

    fn put_active_vault_record(vault_id: [u8; 32], amount_sats: u64, direction: &str) {
        let vid_b32 = crate::util::text_id::encode_base32_crockford(&vault_id);
        crate::storage::client_db::upsert_vault_record(&PersistedVaultRecord {
            vault_op_id: format!("deposit-{vid_b32}-{direction}"),
            direction: direction.to_string(),
            vault_state: "completed".to_string(),
            hash_lock: vec![0x33; 32],
            vault_id: Some(vid_b32),
            btc_amount_sats: amount_sats,
            btc_pubkey: vec![0x03; 33],
            htlc_script: Some(vec![0x66; 64]),
            htlc_address: Some("tb1qtest".to_string()),
            external_commitment: None,
            refund_iterations: 42,
            created_at_state: 1,
            entry_header: Some(vec![0x44; 80]),
            parent_vault_id: None,
            successor_depth: 0,
            is_fractional_successor: false,
            refund_hash_lock: vec![0x22; 32],
            destination_address: None,
            funding_txid: None,
            exit_amount_sats: 0,
            exit_header: None,
            exit_confirm_depth: 0,
            entry_txid: None,
            deposit_nonce: Some(vec![0x55; 32]),
        })
        .unwrap_or_else(|e| panic!("store vault record failed: {e}"));
    }

    fn test_vault_proto(vault_id: [u8; 32], amount_sats: u64) -> Vec<u8> {
        generated::LimboVaultProto {
            id: vault_id.to_vec(),
            fulfillment_condition: Some(generated::FulfillmentMechanism {
                kind: Some(generated::fulfillment_mechanism::Kind::BitcoinHtlc(
                    generated::BitcoinHtlc {
                        hash_lock: vec![0x11; 32],
                        refund_hash_lock: vec![0x22; 32],
                        refund_iterations: 42,
                        bitcoin_pubkey: vec![0x03; 33],
                        expected_btc_amount_sats: amount_sats,
                        network: 0,
                        min_confirmations: 1,
                    },
                )),
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn test_advertisement(
        vault_id: [u8; 32],
        amount_sats: u64,
        routeable: bool,
        updated_state_number: u64,
        lifecycle_state: &str,
    ) -> generated::DbtcVaultAdvertisementV1 {
        let vid_b32 = crate::util::text_id::encode_base32_crockford(&vault_id);
        generated::DbtcVaultAdvertisementV1 {
            version: DBTC_VAULT_ADVERTISEMENT_VERSION,
            policy_commit: BitcoinTapSdk::dbtc_policy_commit().to_vec(),
            vault_id: vid_b32.clone(),
            controller_device_id: vec![0xAB; 32],
            amount_sats,
            successor_depth: 0,
            lifecycle_state: lifecycle_state.to_string(),
            routeable,
            busy_reason: if routeable {
                String::new()
            } else {
                "busy".to_string()
            },
            updated_state_number,
            vault_proto_key: BitcoinTapSdk::vault_proto_key(&vid_b32),
            vault_proto_digest: dsm::crypto::blake3::domain_hash(
                "DSM/vault-ad",
                &test_vault_proto(vault_id, amount_sats),
            )
            .as_bytes()
            .to_vec(),
            entry_txid: vec![0u8; 32],
            htlc_address: String::new(),
            script_commit: vec![],
            redeem_params: vec![],
            deposit_nonce: vec![0x55; 32],
        }
    }

    #[test]
    fn dbtc_token_metadata_correct() {
        let meta = BitcoinTapSdk::dbtc_token_metadata([0xAA; 32]);
        assert_eq!(meta.token_id, "dBTC");
        assert_eq!(meta.symbol, "dBTC");
        assert_eq!(meta.name, "Deterministic Bitcoin");
        assert_eq!(meta.decimals, 8);
        assert_eq!(meta.token_type, TokenType::Wrapped);
        assert_eq!(meta.owner_id, [0xAA; 32]);
        assert_eq!(
            meta.fields.get("backing_asset"),
            Some(&"bitcoin".to_string())
        );
        assert_eq!(
            meta.fields.get("mint_mechanism"),
            Some(&"dlv_native".to_string())
        );
        assert_eq!(
            meta.policy_anchor,
            Some(format!(
                "dsm:policy:{}",
                crate::util::text_id::encode_base32_crockford(
                    crate::policy::builtins::DBTC_POLICY_COMMIT
                )
            ))
        );
    }

    #[test]
    fn dbtc_create_operation_correct() {
        let op = BitcoinTapSdk::dbtc_create_operation([0xBB; 32]);
        match op {
            TokenOperation::Create {
                metadata,
                supply,
                fee,
            } => {
                assert_eq!(metadata.token_id, "dBTC");
                assert_eq!(metadata.token_type, TokenType::Wrapped);
                assert_eq!(supply, TokenSupply::Fixed(DBTC_MAX_SUPPLY_SATS));
                assert_eq!(fee, 0);
            }
            _ => panic!("Expected Create operation"),
        }
    }

    #[test]
    fn vault_op_id_deterministic() {
        let hash_lock = [0x42; 32];
        let id1 = BitcoinTapSdk::generate_vault_op_id(&hash_lock, "vault-123");
        let id2 = BitcoinTapSdk::generate_vault_op_id(&hash_lock, "vault-123");
        assert_eq!(id1, id2);
        assert!(id1.starts_with("deposit-"));
    }

    #[test]
    fn vault_op_id_changes_with_input() {
        let id1 = BitcoinTapSdk::generate_vault_op_id(&[0x42; 32], "vault-a");
        let id2 = BitcoinTapSdk::generate_vault_op_id(&[0x42; 32], "vault-b");
        assert_ne!(id1, id2);
    }

    #[test]
    fn encode_decode_dbtc_content() {
        let amount = 100_000_000u64; // 1 BTC in sats
        let content = BitcoinTapSdk::encode_dbtc_content(amount);
        assert_eq!(content.len(), 12); // 8 (amount) + 4 ("dBTC")
        let decoded = match BitcoinTapSdk::decode_dbtc_content(&content) {
            Ok(decoded) => decoded,
            Err(e) => panic!("Failed to decode dBTC content: {:?}", e),
        };
        assert_eq!(decoded, amount);
    }

    #[test]
    fn external_commitment_deterministic() {
        let hash_lock = [0xAA; 32];
        let state = State::default();
        let c1 = BitcoinTapSdk::create_deposit_commitment(
            &hash_lock,
            "v1",
            "btc_to_dbtc",
            50_000_000,
            &state,
        );
        let c2 = BitcoinTapSdk::create_deposit_commitment(
            &hash_lock,
            "v1",
            "btc_to_dbtc",
            50_000_000,
            &state,
        );
        assert_eq!(c1, c2);

        // Different direction produces different commitment
        let c3 = BitcoinTapSdk::create_deposit_commitment(
            &hash_lock,
            "v1",
            "dbtc_to_btc",
            50_000_000,
            &state,
        );
        assert_ne!(c1, c3);

        // Different amount produces different commitment
        let c4 = BitcoinTapSdk::create_deposit_commitment(
            &hash_lock,
            "v1",
            "btc_to_dbtc",
            100_000_000,
            &state,
        );
        assert_ne!(c1, c4);
    }

    #[test]
    fn seal_tap_correct() {
        let op = BitcoinTapSdk::seal_tap(50_000_000, "deposit-123");
        match op {
            TokenOperation::Lock {
                token_id,
                amount,
                purpose,
            } => {
                assert_eq!(token_id, "dBTC");
                assert_eq!(amount, 50_000_000);
                assert!(String::from_utf8_lossy(&purpose).contains("deposit-123"));
            }
            _ => panic!("Expected Lock operation"),
        }
    }

    #[test]
    fn bearer_eta_deterministic() {
        let seed = [0x42u8; 32];
        let nonce1 = [0x01u8; 32];
        let nonce2 = [0x02u8; 32];
        let seed2 = [0x99u8; 32];

        let e1 = BitcoinTapSdk::derive_bearer_eta(&seed, &nonce1);
        let e2 = BitcoinTapSdk::derive_bearer_eta(&seed, &nonce1);
        let e3 = BitcoinTapSdk::derive_bearer_eta(&seed, &nonce2);
        let e4 = BitcoinTapSdk::derive_bearer_eta(&seed2, &nonce1);

        assert_eq!(e1, e2, "same inputs must produce same η");
        assert_ne!(e1, e3, "different deposit_nonce must produce different η");
        assert_ne!(e1, e4, "different manifold_seed must produce different η");

        let s1 = BitcoinTapSdk::derive_preimage_from_eta(&e1);
        let s2 = BitcoinTapSdk::derive_preimage_from_eta(&e1);
        assert_eq!(s1, s2, "same η must produce same preimage");
        assert_eq!(s1.len(), 32);

        let s3 = BitcoinTapSdk::derive_preimage_from_eta(&e3);
        assert_ne!(s1, s3, "different η must produce different preimages");
    }

    #[test]
    fn withdrawal_route_prefers_single_full_exact_match() {
        let full_fee = estimated_full_withdrawal_fee_sats();
        let requested_net_sats = 200_000;
        let route = BitcoinTapSdk::select_withdrawal_route(
            &[
                withdrawable_vault("vault-exact", requested_net_sats + full_fee, 0),
                withdrawable_vault("vault-larger", requested_net_sats + full_fee + 50_000, 0),
            ],
            requested_net_sats,
        )
        .unwrap_or_else(|| panic!("expected exact route"));

        assert_eq!(route.planned_net_sats, requested_net_sats);
        assert_eq!(route.legs.len(), 1);
        assert_eq!(route.legs[0].vault_id, "vault-exact");
        assert_eq!(route.legs[0].kind, WithdrawalLegKind::Full);
    }

    #[test]
    fn withdrawal_route_uses_multiple_fulls_plus_partial_for_exact_match() {
        let params = DbtcParams::resolve();
        let full_fee = estimated_full_withdrawal_fee_sats();
        let partial_fee = estimated_partial_withdrawal_fee_sats();
        let min_remainder = params.min_vault_balance_sats.max(params.dust_floor_sats);
        let requested_net_sats = 200_000;

        let route = BitcoinTapSdk::select_withdrawal_route(
            &[
                withdrawable_vault("a-full", 120_000 + full_fee, 0),
                withdrawable_vault("z-partial", min_remainder + 80_000 + partial_fee, 0),
            ],
            requested_net_sats,
        )
        .unwrap_or_else(|| panic!("expected exact route"));

        assert_eq!(route.planned_net_sats, requested_net_sats);
        assert_eq!(route.legs.len(), 2);
        assert_eq!(route.legs[0].vault_id, "a-full");
        assert_eq!(route.legs[0].kind, WithdrawalLegKind::Full);
        assert_eq!(route.legs[1].vault_id, "z-partial");
        assert_eq!(route.legs[1].kind, WithdrawalLegKind::Partial);
        assert_eq!(route.legs[1].remainder_sats, min_remainder);
    }

    #[test]
    fn withdrawal_route_returns_best_lower_partial_match() {
        let params = DbtcParams::resolve();
        let partial_fee = estimated_partial_withdrawal_fee_sats();
        let min_remainder = params.min_vault_balance_sats.max(params.dust_floor_sats);
        let requested_net_sats = 50_000;

        let route = BitcoinTapSdk::select_withdrawal_route(
            &[withdrawable_vault(
                "vault-lower",
                min_remainder + 30_000 + partial_fee,
                0,
            )],
            requested_net_sats,
        )
        .unwrap_or_else(|| panic!("expected best lower route"));

        assert_eq!(route.planned_net_sats, 30_000);
        assert_eq!(route.legs.len(), 1);
        assert_eq!(route.legs[0].kind, WithdrawalLegKind::Partial);
        assert_eq!(route.total_fee_sats, partial_fee);
    }

    #[test]
    fn withdrawal_route_rejects_partial_when_successor_depth_exhausted() {
        let params = DbtcParams::resolve();
        let partial_fee = estimated_partial_withdrawal_fee_sats();
        let min_remainder = params.min_vault_balance_sats.max(params.dust_floor_sats);

        let route = BitcoinTapSdk::select_withdrawal_route(
            &[withdrawable_vault(
                "vault-max-depth",
                min_remainder + 50_000 + partial_fee,
                params.max_successor_depth,
            )],
            50_000,
        );

        assert!(
            route.is_none(),
            "partial route should be blocked at max depth"
        );
    }

    #[test]
    fn withdrawal_route_uses_stable_tiebreaker_for_equal_exact_matches() {
        let full_fee = estimated_full_withdrawal_fee_sats();
        let requested_net_sats = 150_000;

        let route = BitcoinTapSdk::select_withdrawal_route(
            &[
                withdrawable_vault("vault-a", requested_net_sats + full_fee, 0),
                withdrawable_vault("vault-b", requested_net_sats + full_fee, 0),
            ],
            requested_net_sats,
        )
        .unwrap_or_else(|| panic!("expected exact route"));

        assert_eq!(route.legs.len(), 1);
        assert_eq!(route.legs[0].vault_id, "vault-a");
    }

    #[test]
    fn busy_vault_reason_detects_exit_and_successor_states() {
        let exit_reason = BitcoinTapSdk::busy_vault_reason(
            &[persisted_deposit_record(
                "dbtc_to_btc",
                "awaiting_confirmation",
                Some("vault-a"),
                None,
                false,
            )],
            &[],
        )
        .unwrap_or_else(|| panic!("expected active exit reason"));
        assert!(exit_reason.contains("Exit already in progress"));

        let successor_reason = BitcoinTapSdk::busy_vault_reason(
            &[],
            &[persisted_deposit_record(
                "btc_to_dbtc",
                "BurnPending",
                Some("vault-b-child"),
                Some("vault-b"),
                true,
            )],
        )
        .unwrap_or_else(|| panic!("expected successor reason"));
        assert!(successor_reason.contains("Successor vault still pending confirmation"));
    }

    // dBTC planner tests use BLAKE3-derived 32-byte ids via `vid_from_label`
    // so they round-trip through the strict `LimboVaultProto.id` schema.  The
    // wire-level vault_id (and assertions) are the Base32-Crockford encoding
    // of those bytes, kept consistent through `encode_base32_crockford`.
    #[tokio::test]
    #[serial]
    async fn global_selector_dedupes_by_latest_updated_state_number() {
        init_withdrawal_test_db();

        let bridge = BitcoinTapSdk::new(Arc::new(DLVManager::new()));
        let dedupe_vid = vid_from_label("vault-dedupe");
        let dedupe_b32 = crate::util::text_id::encode_base32_crockford(&dedupe_vid);
        put_active_vault(dedupe_vid, 250_000);
        put_active_vault_record(dedupe_vid, 250_000, "btc_to_dbtc");

        let stale_ad = test_advertisement(dedupe_vid, 111_000, true, 1, "active");
        let fresh_ad = test_advertisement(dedupe_vid, 250_000, true, 9, "active");
        BitcoinTapSdk::seed_dbtc_storage_object(
            format!(
                "{}{dedupe_b32}-stale",
                BitcoinTapSdk::vault_advertisement_prefix(),
            ),
            stale_ad.encode_to_vec(),
        );
        BitcoinTapSdk::seed_dbtc_storage_object(
            format!(
                "{}{dedupe_b32}-fresh",
                BitcoinTapSdk::vault_advertisement_prefix(),
            ),
            fresh_ad.encode_to_vec(),
        );

        let selector = bridge
            .build_global_selector_input(None, None)
            .await
            .unwrap_or_else(|e| panic!("build selector failed: {e}"));

        assert_eq!(selector.eligible.len(), 1);
        assert_eq!(selector.eligible[0].vault_id, dedupe_b32);
        assert_eq!(selector.eligible[0].amount_sats, 250_000);
        assert!(
            selector.blocked.is_empty(),
            "deduped selector should not block the fresh advertisement: {:?}",
            selector.blocked
        );
    }

    #[tokio::test]
    #[serial]
    async fn global_selector_makes_remote_vault_eligible_when_artifacts_valid() {
        init_withdrawal_test_db();

        let bridge = BitcoinTapSdk::new(Arc::new(DLVManager::new()));
        let remote_vid = vid_from_label("remote-vault-a");
        let remote_b32 = crate::util::text_id::encode_base32_crockford(&remote_vid);
        let remote_ad = test_advertisement(remote_vid, 300_000, true, 2, "active");
        BitcoinTapSdk::seed_dbtc_storage_object(
            BitcoinTapSdk::vault_advertisement_key(&remote_b32),
            remote_ad.encode_to_vec(),
        );
        BitcoinTapSdk::seed_dbtc_storage_object(
            remote_ad.vault_proto_key.clone(),
            test_vault_proto(remote_vid, 300_000),
        );

        let selector = bridge
            .build_global_selector_input(None, None)
            .await
            .unwrap_or_else(|e| panic!("build selector failed: {e}"));

        // Remote vaults with valid artifacts are now eligible (dBTC §6.2).
        // The vault is loaded from storage nodes into memory at withdrawal time.
        assert_eq!(selector.eligible.len(), 1);
        assert_eq!(selector.eligible[0].vault_id, remote_b32);
        assert_eq!(selector.eligible[0].amount_sats, 300_000);
    }

    #[tokio::test]
    #[serial]
    async fn plan_withdrawal_produces_stable_plan_id_and_legs() {
        init_withdrawal_test_db();

        let bridge = BitcoinTapSdk::new(Arc::new(DLVManager::new()));
        let desired_net_sats = 150_000;
        let full_fee = estimated_full_withdrawal_fee_sats();
        let gross = desired_net_sats + full_fee;
        let route_vid = vid_from_label("vault-route");
        let route_b32 = crate::util::text_id::encode_base32_crockford(&route_vid);
        put_active_vault(route_vid, gross);
        put_active_vault_record(route_vid, gross, "btc_to_dbtc");

        let plan = bridge
            .plan_withdrawal(gross, "tb1qexactroute", &[0x11; 32])
            .await
            .unwrap_or_else(|e| panic!("plan withdrawal failed: {e}"));

        assert_eq!(plan.legs.len(), 1);
        assert!(!plan.plan_id.is_empty());
        assert_eq!(plan.requested_net_sats, desired_net_sats);
        assert_eq!(plan.legs[0].vault_id, route_b32);
    }

    #[tokio::test]
    #[serial]
    async fn plan_withdrawal_ignores_stale_in_memory_vaults_not_in_sqlite() {
        init_withdrawal_test_db();

        let dlv = Arc::new(DLVManager::new());
        let bridge = BitcoinTapSdk::new(dlv.clone());

        let full_fee = estimated_full_withdrawal_fee_sats();
        let desired_net_sats = 1_501_337;
        let gross = desired_net_sats + full_fee;
        // Order-sensitive ids: the planner picks the lex-smallest Base32 form
        // first when ties occur, so deriving from "000-…" / "001-…" labels is
        // not enough — the BLAKE3 hash output ordering is what governs.  Use
        // labels that order deterministically through encode_base32_crockford.
        let preferred_vid = vid_from_label("000-vault-a");
        let secondary_vid = vid_from_label("001-vault-b");
        let preferred_b32 = crate::util::text_id::encode_base32_crockford(&preferred_vid);
        let secondary_b32 = crate::util::text_id::encode_base32_crockford(&secondary_vid);
        let stale_vid = {
            let mut v = [0u8; 32];
            v[..13].copy_from_slice(b"stale-vault-0");
            v
        };
        let stale_b32 = crate::util::text_id::encode_base32_crockford(&stale_vid);

        let mut stale_vault = LimboVault::new_minimal(
            stale_vid,
            FulfillmentMechanism::BitcoinHTLC {
                hash_lock: [0x10; 32],
                refund_hash_lock: [0x20; 32],
                refund_iterations: 42,
                bitcoin_pubkey: vec![0x03; 33],
                expected_btc_amount_sats: gross,
                network: 0,
                min_confirmations: 1,
            },
            [0x99; 32],
        );
        stale_vault.state = VaultState::Active;
        dlv.add_vault(stale_vault)
            .await
            .unwrap_or_else(|e| panic!("add stale vault failed: {e}"));

        put_active_vault(secondary_vid, gross);
        put_active_vault_record(secondary_vid, gross, "btc_to_dbtc");
        put_active_vault(preferred_vid, gross);
        put_active_vault_record(preferred_vid, gross, "btc_to_dbtc");

        let plan = bridge
            .plan_withdrawal(gross, "tb1qexampledestination", &[0x11; 32])
            .await
            .unwrap_or_else(|e| panic!("plan withdrawal failed: {e}"));

        assert_eq!(plan.legs.len(), 1);
        // Whichever of the two SQLite-authoritative vaults the planner picks
        // (deterministic by Base32 ordering), it must NOT be the stale
        // in-memory vault that was never persisted to SQLite.
        assert!(
            plan.legs[0].vault_id == preferred_b32 || plan.legs[0].vault_id == secondary_b32,
            "deterministic selection should use SQLite-authoritative membership; \
             got {} (preferred={preferred_b32}, secondary={secondary_b32})",
            plan.legs[0].vault_id,
        );
        assert!(
            plan.legs.iter().all(|leg| leg.vault_id != stale_b32),
            "stale in-memory vaults absent from SQLite must not be considered"
        );
    }
}
