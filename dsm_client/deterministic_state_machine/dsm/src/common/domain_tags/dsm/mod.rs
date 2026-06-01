// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM-prefixed domain tag constants grouped by protocol surface.

mod bilateral_transport;
mod core;
mod crypto_keys;
mod genesis_identity;
mod misc;
mod policy_registry;
mod recovery;
mod vault_dbtc;

pub use bilateral_transport::*;
pub use core::*;
pub use crypto_keys::*;
pub use genesis_identity::*;
pub use misc::*;
pub use policy_registry::*;
pub use recovery::*;
pub use vault_dbtc::*;

#[cfg(test)]
pub(super) fn all_tags() -> Vec<&'static str> {
    let mut tags = Vec::new();
    tags.extend_from_slice(core::TAGS);
    tags.extend_from_slice(bilateral_transport::TAGS);
    tags.extend_from_slice(crypto_keys::TAGS);
    tags.extend_from_slice(genesis_identity::TAGS);
    tags.extend_from_slice(misc::TAGS);
    tags.extend_from_slice(policy_registry::TAGS);
    tags.extend_from_slice(recovery::TAGS);
    tags.extend_from_slice(vault_dbtc::TAGS);
    tags
}
