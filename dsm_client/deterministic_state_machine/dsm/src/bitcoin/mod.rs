// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bitcoin primitives for dBTC taps (Explainer §64: DSM taps Bitcoin; it does not bridge it).
//!
//! Provides SPV proof verification, the dual-hashlock script, header-chain checks and the
//! Bitcoin types a vault's deposit and withdrawal use.
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
