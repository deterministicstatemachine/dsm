//! Deterministic Limbo Vault (DLV) Implementation
//!
//! Core implementation of quantum-resistant cryptographic vaults.
//!
//! ## Keg & Tap Vocabulary (§dBTC spec)
//!
//! The whitepaper uses a "keg and tap" metaphor for the Bitcoin tap:
//!
//! | Paper Term      | Code Type                      | Meaning                          |
//! |-----------------|--------------------------------|----------------------------------|
//! | Keg             | (Bitcoin blockchain)           | Global collateral pool           |
//! | Tap             | `LimboVault` + `BitcoinHTLC`   | One HTLC-locked vault            |
//! | Open Tap        | `open_tap()`                   | BTC → dBTC deposit               |
//! | Draw Tap        | `draw_tap()`                   | Finalize deposit (mint or burn)  |
//! | Plan Withdraw   | `plan_withdrawal()`            | Authoritative dBTC → BTC route   |
//! | Pour Partial    | `pour_partial()`               | Internal partial sweep leg       |
//! | Drain Tap       | `drain_tap()`                  | Internal full sweep leg          |
//! | Close Tap       | `close_tap()`                  | Budget-exhaustion refund         |
//! | Seal Tap        | `seal_tap()`                   | Lock dBTC for withdrawal         |

pub mod asset_manager;
pub mod dlv_manager;
pub mod fulfillment;
pub mod limbo_vault;

pub use asset_manager::*;
pub use dlv_manager::*;
pub use fulfillment::*;
pub use limbo_vault::*;

/// Keg/Tap vocabulary aliases (§dBTC spec).
/// A `BitcoinTap` is a `LimboVault` with a `BitcoinHTLC` fulfillment mechanism —
/// it connects Bitcoin collateral (the "keg") to DSM dBTC tokens.
pub type BitcoinTap = LimboVault;

/// The `KegManager` manages the set of active taps (DLVs backed by Bitcoin HTLCs).
pub type KegManager = DLVManager;
