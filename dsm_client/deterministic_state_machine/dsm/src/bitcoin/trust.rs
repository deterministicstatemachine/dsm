//! Formal trust-boundary predicates for dBTC settlement verification.
//!
//! This module is the code-side correspondence boundary for the formal dBTC
//! trust-reduction work in:
//! - `tla/DSM_dBTC_TrustReduction.tla`
//! - `lean4/DSM_dBTC_TrustReduction.lean`
//!
//! It does **not** prove Bitcoin consensus from first principles. Instead it
//! names the exact runtime predicates the Rust verifier is expected to enforce.
//! On mainnet, runtime acceptance must imply the formal `RustVerifierAccepted`
//! predicate. On signet/testnet, runtime behavior is intentionally weaker due
//! to checkpoint and entry-anchor bypasses used for development/testing.

use super::types::BitcoinNetwork;

/// Trust profile exposed by the active network path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RustVerifierTrustProfile {
    /// Mainnet path: runtime acceptance is intended to imply the formal
    /// `RustVerifierAccepted` predicate from the Lean/TLA artifacts.
    MainnetFormal,
    /// Development/test path: runtime acceptance is intentionally weaker than
    /// the formal mainnet predicate because checkpoint and/or entry-anchor
    /// enforcement is bypassed.
    WeakenedDevelopment,
}

/// Runtime-observed Bitcoin settlement facts.
///
/// Corresponds to the proof vocabulary:
/// - `bitcoinSpend`
/// - `confDepth`
/// - `dmin`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitcoinSettlementObservation {
    pub network: BitcoinNetwork,
    pub bitcoin_spend_observed: bool,
    pub confirmation_depth: u64,
    pub min_confirmations: u64,
}

impl BitcoinSettlementObservation {
    /// `bitcoinSpend(w) ∧ conf(w) ≥ dmin(P(w))`
    pub fn meets_confirmation_gate(&self) -> bool {
        self.bitcoin_spend_observed && self.confirmation_depth >= self.min_confirmations
    }

    pub fn trust_profile(&self) -> RustVerifierTrustProfile {
        match self.network {
            BitcoinNetwork::Mainnet => RustVerifierTrustProfile::MainnetFormal,
            BitcoinNetwork::Testnet | BitcoinNetwork::Signet => {
                RustVerifierTrustProfile::WeakenedDevelopment
            }
        }
    }
}

/// Full verifier evidence at the point Rust decides whether the Bitcoin-side
/// settlement proof is accepted.
///
/// The boolean fields correspond 1:1 to the formal predicates used by the
/// proof artifacts:
/// - `spv_inclusion_valid`  ↔ `spvValid`
/// - `pow_valid`            ↔ `powValid`
/// - `checkpoint_rooted`    ↔ `checkpointed`
/// - `same_chain_anchored`  ↔ `sameChain`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RustVerifierAcceptedEvidence {
    pub observation: BitcoinSettlementObservation,
    pub spv_inclusion_valid: bool,
    pub pow_valid: bool,
    pub checkpoint_rooted: bool,
    /// Vacuously `true` when there is no prior entry anchor to relate against.
    pub same_chain_anchored: bool,
}

impl RustVerifierAcceptedEvidence {
    /// Formal mainnet predicate used by the Lean/TLA trust-reduction artifacts.
    ///
    /// This corresponds to `RustVerifierAccepted` in
    /// `lean4/DSM_dBTC_TrustReduction.lean`.
    pub fn rust_verifier_accepted(&self) -> bool {
        matches!(
            self.observation.trust_profile(),
            RustVerifierTrustProfile::MainnetFormal
        ) && self.observation.meets_confirmation_gate()
            && self.spv_inclusion_valid
            && self.pow_valid
            && self.checkpoint_rooted
            && self.same_chain_anchored
    }

    /// Actual runtime acceptance under the current network policy.
    ///
    /// - On mainnet, this is intentionally identical to
    ///   `rust_verifier_accepted()`.
    /// - On signet/testnet, runtime acceptance is weaker because checkpoint and
    ///   entry-anchor enforcement are intentionally bypassed.
    pub fn runtime_accepts(&self) -> bool {
        match self.observation.trust_profile() {
            RustVerifierTrustProfile::MainnetFormal => self.rust_verifier_accepted(),
            RustVerifierTrustProfile::WeakenedDevelopment => {
                self.observation.meets_confirmation_gate()
                    && self.spv_inclusion_valid
                    && self.pow_valid
            }
        }
    }

    /// Code-level theorem boundary used by docs/comments:
    /// on mainnet, runtime acceptance implies the formal predicate.
    pub fn runtime_acceptance_implies_formal_mainnet(&self) -> bool {
        match self.observation.trust_profile() {
            RustVerifierTrustProfile::MainnetFormal => {
                !self.runtime_accepts() || self.rust_verifier_accepted()
            }
            RustVerifierTrustProfile::WeakenedDevelopment => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_runtime_acceptance_matches_formal_predicate() {
        let evidence = RustVerifierAcceptedEvidence {
            observation: BitcoinSettlementObservation {
                network: BitcoinNetwork::Mainnet,
                bitcoin_spend_observed: true,
                confirmation_depth: 100,
                min_confirmations: 100,
            },
            spv_inclusion_valid: true,
            pow_valid: true,
            checkpoint_rooted: true,
            same_chain_anchored: true,
        };

        assert!(evidence.rust_verifier_accepted());
        assert!(evidence.runtime_accepts());
        assert!(evidence.runtime_acceptance_implies_formal_mainnet());
    }

    #[test]
    fn weakened_network_can_accept_without_formal_mainnet_predicate() {
        let evidence = RustVerifierAcceptedEvidence {
            observation: BitcoinSettlementObservation {
                network: BitcoinNetwork::Signet,
                bitcoin_spend_observed: true,
                confirmation_depth: 1,
                min_confirmations: 1,
            },
            spv_inclusion_valid: true,
            pow_valid: true,
            checkpoint_rooted: false,
            same_chain_anchored: false,
        };

        assert!(!evidence.rust_verifier_accepted());
        assert!(evidence.runtime_accepts());
        assert!(!evidence.runtime_acceptance_implies_formal_mainnet());
    }

    #[test]
    fn missing_confirmation_gate_blocks_all_profiles() {
        let evidence = RustVerifierAcceptedEvidence {
            observation: BitcoinSettlementObservation {
                network: BitcoinNetwork::Mainnet,
                bitcoin_spend_observed: true,
                confirmation_depth: 99,
                min_confirmations: 100,
            },
            spv_inclusion_valid: true,
            pow_valid: true,
            checkpoint_rooted: true,
            same_chain_anchored: true,
        };

        assert!(!evidence.rust_verifier_accepted());
        assert!(!evidence.runtime_accepts());
    }
}
