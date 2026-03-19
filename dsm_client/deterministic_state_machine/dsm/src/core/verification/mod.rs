//! Core verification mechanisms for DSM state transitions.
//!
//! Based on whitepaper Sections 23 and 30. Provides dual-mode verification
//! supporting both bilateral (`V(S_n, S_{n+1}, σ_A, σ_B)`) and unilateral
//! (`V_uni(S_n, S_{n+1}, σ_A, D_verify(ID_B))`) verification paths, plus
//! identity verification for anchoring and authentication.

pub mod dual_mode_verifier;
pub mod identity_verifier;

pub use dual_mode_verifier::DualModeVerifier;
pub use identity_verifier::IdentityVerifier;
