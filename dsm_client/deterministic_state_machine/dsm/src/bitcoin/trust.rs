// SPDX-License-Identifier: MIT OR Apache-2.0

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
        // Issue #181 Finding 2 fix: `WeakenedDevelopment` is only reachable
        // when the `bitcoin-testnet-bypass` feature is enabled at build
        // time. Production builds (feature off) select `MainnetFormal` for
        // every network, so a corrupted or downgraded network selector
        // cannot weaken the trust profile at runtime.
        match self.network {
            BitcoinNetwork::Mainnet => RustVerifierTrustProfile::MainnetFormal,
            BitcoinNetwork::Testnet | BitcoinNetwork::Signet => {
                #[cfg(feature = "bitcoin-testnet-bypass")]
                {
                    RustVerifierTrustProfile::WeakenedDevelopment
                }
                #[cfg(not(feature = "bitcoin-testnet-bypass"))]
                {
                    RustVerifierTrustProfile::MainnetFormal
                }
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

    // Issue #181 Finding 2: this test is only meaningful when the
    // `bitcoin-testnet-bypass` feature is enabled. Without it, Testnet/Signet
    // select `MainnetFormal` (default-secure) and weakened acceptance is
    // unreachable — which is exactly what the new test below pins.
    #[cfg(feature = "bitcoin-testnet-bypass")]
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

    // Issue #181 Finding 2 regression — with the bypass feature OFF
    // (default), Signet and Testnet are treated as MainnetFormal: weak
    // evidence that previously cleared the WeakenedDevelopment profile is
    // now rejected.
    #[cfg(not(feature = "bitcoin-testnet-bypass"))]
    #[test]
    fn default_build_treats_signet_testnet_as_mainnet_formal() {
        for net in [BitcoinNetwork::Signet, BitcoinNetwork::Testnet] {
            let evidence = RustVerifierAcceptedEvidence {
                observation: BitcoinSettlementObservation {
                    network: net,
                    bitcoin_spend_observed: true,
                    confirmation_depth: 1,
                    min_confirmations: 1,
                },
                spv_inclusion_valid: true,
                pow_valid: true,
                checkpoint_rooted: false,   // would have passed under bypass
                same_chain_anchored: false, // would have passed under bypass
            };
            assert_eq!(
                evidence.observation.trust_profile(),
                RustVerifierTrustProfile::MainnetFormal,
                "{net:?} must select MainnetFormal when bypass feature is off"
            );
            assert!(
                !evidence.runtime_accepts(),
                "{net:?} weak evidence must NOT be accepted in default-secure build"
            );
        }
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
