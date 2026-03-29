//! src/core/token/mod.rs

pub mod era_token;
pub mod init;
pub mod policy;
pub mod token_factory;
pub mod token_registry;
pub mod token_state_manager;

// Optional modules (enable via Cargo features)
#[cfg(feature = "faucet")]
pub mod faucet;

// JNI bridge moved to dsm_sdk - see dsm_sdk/src/jni/unified_protobuf_bridge.rs

// Export main token manager types and helpers (only items that exist)
pub use era_token::{EraTokenManager, NetworkType};
pub use init::{initialize_root_token, initialize_root_token_with_balance};
pub use policy::TokenPolicySystem;

pub use token_factory::{
    create_token_genesis, derive_sub_token_genesis, ParticipantId, TokenContribution, TokenGenesis,
};

pub use token_registry::TokenRegistry;
pub use token_state_manager::{
    builtin_policy_commit_for_token, derive_canonical_balance_key, resolve_policy_commit,
    PolicyCommitResolver, TokenStateManager, TokenTransfer,
};

// Re-export faucet only when enabled and implemented
#[cfg(feature = "faucet")]
pub use faucet::{EraFaucet, FaucetClaim, FaucetClaimResult, FaucetConfig};
