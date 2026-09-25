// SPDX-License-Identifier: MIT OR Apache-2.0

//! Identity: the device's mnemonic-rooted genesis (Genesis v2/v3), its
//! self-proving directory entry, and the resolution of the device-authority
//! chain from `G` (the P0–P6 predicate).

pub mod authority_resolver;
pub mod directory;
pub mod genesis;
pub mod genesis_v2;
pub mod genesis_v3;

pub use crate::core::identity::genesis::GenesisState;
