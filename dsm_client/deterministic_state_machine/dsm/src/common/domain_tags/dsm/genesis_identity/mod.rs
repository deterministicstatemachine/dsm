// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: genesis identity

// TAGS below is consumed only by the cfg(test) `all_tags()` collector, so
// both it and this import are test-only in a non-test build.
#[cfg(test)]
use crate::crypto::domain::TaggedHashDomain;

mod device;
mod genesis;
mod identity;
mod system;

pub use device::*;
pub use genesis::*;
pub use identity::*;
pub use system::*;

#[cfg(test)]
#[cfg(test)]
pub(super) const TAGS: &[TaggedHashDomain<'static>] = &[
    TAG_DSM_CONTACT_GENESIS,
    TAG_DSM_DEVICE,
    TAG_DSM_DEVICE_ENTROPY,
    TAG_DSM_DEVICE_FINGERPRINT,
    TAG_DSM_DEVICE_ID_GEN,
    TAG_DSM_DEVID,
    TAG_DSM_ERROR_ENVELOPE_DEVICE,
    TAG_DSM_ERROR_ENVELOPE_GENESIS,
    TAG_DSM_GENESIS,
    TAG_DSM_GENESIS_COMMIT,
    TAG_DSM_GENESIS_CONTRIB_V2,
    TAG_DSM_GENESIS_DEVICE_COMMIT,
    TAG_DSM_GENESIS_DEVICE_ENTROPY,
    TAG_DSM_GENESIS_ENTROPY,
    TAG_DSM_GENESIS_ENTROPY_PAD,
    TAG_DSM_GENESIS_HASH,
    TAG_DSM_GENESIS_INITIAL_ENTROPY,
    TAG_DSM_GENESIS_MERKLE,
    TAG_DSM_GENESIS_NONCE_V2,
    TAG_DSM_GENESIS_V2,
    TAG_DSM_GENESIS_VERIFY,
    TAG_DSM_IDENTITY_ANCHOR,
    TAG_DSM_IDENTITY_CLAIM,
    TAG_DSM_IDENTITY_COMBINE,
    TAG_DSM_IDENTITY_DID,
    TAG_DSM_IDENTITY_HASH,
    TAG_DSM_IDENTITY_ID,
    TAG_DSM_IDENTITY_LABEL,
    TAG_DSM_IDENTITY_MPC_ID,
    TAG_DSM_IDENTITY_SEED_ENTROPY,
    TAG_DSM_LOCAL_ID,
    TAG_DSM_MANIFOLD_SEED,
    TAG_DSM_SUB_GENESIS_DEVICE_ENTROPY,
    TAG_DSM_SYSTEM_FEE_DEVICE,
];
