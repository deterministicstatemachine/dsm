// Crypto Verification Module
//
// This module implements pure cryptographic verification mechanisms using
// cryptography and hardware-specific identifiers instead of hardware-based
// secure modules as described in the DSM whitepaper.
//
// This approach uses purely mathematical guarantees through cryptographic primitives
// to ensure security, verification, and deterministic state evolution.

pub mod multiparty_computation;
pub mod quantum_resistant_binding;
#[cfg(test)]
mod storage_integration_test;

// Re-export core components for easier access
pub use multiparty_computation::MpcIdentityFactory;
pub use multiparty_computation::MpcContribution;
pub use quantum_resistant_binding::QuantumResistantBinding;
