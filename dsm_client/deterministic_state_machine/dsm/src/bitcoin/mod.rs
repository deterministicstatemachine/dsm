//! Bitcoin primitives for the DSM-Bitcoin bridge (deposits/withdrawals via HTLC vaults).
//!
//! Provides SPV proof verification, HTLC script construction, and
//! Bitcoin-specific types needed for bidirectional dBTC bridge operations.
//! No wall clocks — all verification is deterministic and state-based.

pub mod header_chain;
pub mod script;
pub mod spv;
pub mod trust;
pub mod types;

pub use header_chain::{verify_header_chain, Checkpoint};
pub use script::{build_htlc_script, htlc_p2wsh_address, verify_htlc_script};
pub use spv::{verify_spv_proof, verify_block_header_work, SpvProof};
pub use trust::{BitcoinSettlementObservation, RustVerifierAcceptedEvidence, RustVerifierTrustProfile};
pub use types::{BitcoinNetwork, BtcAmount};
