// SPDX-License-Identifier: MIT OR Apache-2.0

//! SoFi orchestration: one entry per route of SoFi §27, running the stages of
//! §28–§33 in order over the producers in `sofi_sdk`, the publication and
//! evidence acquisition in `sofi_publish` / `sofi_evidence`, and the
//! fulfillment, completion and resolution steps in `sofi_advance`.
//!
//! Producers assemble and publish; Core decides (§26). Nothing here interprets
//! a storage read, skips a Core check, or advances state other than through
//! the Core transition with Core's result unchanged.
//!
//! This module holds the intents the routes hand in and the outcomes they get
//! back.

type D32 = [u8; 32];

/// `sofi.createVault` (§28). The beta market family (constant product, exact
/// input) and release family (the owner's full close) are fixed, so the
/// owner's choices are the pair, the reserves and the fee. The storage set is
/// the network's pinned set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateVaultIntent {
    /// `token_a < token_b`, bytewise: the market policy refuses any other
    /// order rather than swapping it.
    pub token_a_policy_commit: D32,
    pub token_b_policy_commit: D32,
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub fee_bps: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultCreated {
    pub vault_id: D32,
    /// The owner's economic position whose transition carries the creation.
    pub position: u64,
}

/// `sofi.setup` (§29).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupIntent {
    pub vault_id: D32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetUp {
    /// ρ.
    pub setup_ref: D32,
    pub position: u64,
}

/// `sofi.findRoute` (§30): path search over walked heads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindRouteIntent {
    pub token_in_policy_commit: D32,
    pub token_out_policy_commit: D32,
    pub amount_in: u64,
}

/// One hop of a proposed route, priced at the vault's walked head. Carries no
/// authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hop {
    pub vault_id: D32,
    pub parent_root: D32,
    pub token_in_policy_commit: D32,
    pub token_out_policy_commit: D32,
    pub amount_in: u64,
    pub amount_out: u64,
}

/// `sofi.trade` and `sofi.route` (§31): one hop, or several through distinct
/// vaults in hop order, all or none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeIntent {
    pub vault_ids: Vec<D32>,
    pub token_in_policy_commit: D32,
    pub amount_in: u64,
    pub min_amount_out: u64,
}

/// `sofi.close` (§32).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseIntent {
    pub vault_id: D32,
}

/// `sofi.relay` (§33).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayIntent {
    pub trader_genesis: D32,
    pub trader_device_id: D32,
    pub position: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relayed {
    pub cells_written: u32,
}

/// Where a trade, route, close or resolve left the device's position.
/// Predicates are Valid or Invalid only; `RetriesExhausted` is the separate
/// network status: the predicates held, and the network retries ran out
/// before the position resolved (owner, 2026-09-23). Nothing is recorded for
/// it, and the device may try again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionState {
    Realized,
    /// Nothing executed and no balance moved.
    Void,
    /// The predicates failed.
    Invalid,
    /// The predicates held; the network retries were exhausted.
    RetriesExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PositionOutcome {
    pub position: u64,
    pub state: PositionState,
}
