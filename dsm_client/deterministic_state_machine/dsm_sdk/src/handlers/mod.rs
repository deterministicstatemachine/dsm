// SPDX-License-Identifier: MIT OR Apache-2.0

//! # SDK Handler Implementations
//!
//! Concrete implementations of the core bridge traits (`AppRouter`,
//! `BilateralHandler`, `UnilateralHandler`, `RecoveryHandler`,
//! `BootstrapHandler`) that connect the JNI/FFI boundary to the pure
//! `dsm` core library. Each handler is installed into both the SDK
//! dispatch layer and the core bridge layer during [`init_dsm_sdk`](crate::init::init_dsm_sdk).

pub mod app_router_impl;
pub mod bilateral_impl;
pub mod bilateral_settlement;
pub mod core_bridge_adapters;
pub use bilateral_settlement::DefaultBilateralSettlementDelegate;
pub mod unilateral_impl;

pub use app_router_impl::AppRouterImpl;
pub use bilateral_impl::BiImpl;
pub use core_bridge_adapters::{install_app_router_adapter, is_app_router_installed};
pub mod anchor_routes;
pub mod bilateral_routes;
pub mod bitcoin_helpers;
pub mod bitcoin_invoke_routes;
pub mod bitcoin_query_routes;
pub mod contacts_routes;
pub mod dlv_routes;
pub mod faucet_routes;
pub mod identity_routes;
pub mod inbox_routes;
pub mod mempool_api;
pub mod message_routes;
pub mod misc_routes;
pub mod offline_cash_routes;
pub mod online_finalize;
pub mod recipient_receipt;
pub mod posted_dlv_routes;
pub mod prefs_routes;
pub mod recovery_impl;
pub mod recovery_routes;
pub mod relationship_status;
pub mod response_helpers;
pub mod route_routes;
pub mod session_routes;
pub mod sofi_routes;
pub mod storage_routes;
pub mod system_routes;
pub mod token_routes;
pub mod transfer_helpers;
pub mod wallet_routes;
pub use recovery_impl::RecoveryImpl;
pub(crate) use system_routes::{
    handle_create_genesis_v2_query, handle_generate_mnemonic_query, handle_system_genesis_query,
};
pub use unilateral_impl::UniImpl;
