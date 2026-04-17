//! Security Module
//!
//! This module implements security mechanisms described in the whitepaper,
//! including bilateral control resistance. (Former manipulation_resistance
//! module deleted: 804-line struct of &[State]-walking checks with zero
//! external callers. Its responsibilities are now enforced inline:
//! double-spend by Tripwire at SMT leaf level (§6.1), balance conservation
//! by advance()'s balance-witness check (§8), signature chain by bilateral
//! pair signing, commitment binding by §4.2 stitched receipts.)

mod bilateral_control;

pub use bilateral_control::BilateralControlResistance;
pub use bilateral_control::DecentralizedStorage;
