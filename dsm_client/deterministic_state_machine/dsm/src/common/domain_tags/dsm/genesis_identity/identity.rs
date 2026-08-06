// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: identity claim and label domains

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_IDENTITY_ANCHOR: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/identity/anchor");
pub const TAG_DSM_IDENTITY_CLAIM: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/identity/claim");
pub const TAG_DSM_IDENTITY_COMBINE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/identity-combine");
pub const TAG_DSM_IDENTITY_DID: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/identity-did");
pub const TAG_DSM_IDENTITY_HASH: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/identity-hash");
pub const TAG_DSM_IDENTITY_ID: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/identity-id");
pub const TAG_DSM_IDENTITY_LABEL: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/identity-label");
pub const TAG_DSM_IDENTITY_MPC_ID: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/identity-mpc-id");
pub const TAG_DSM_IDENTITY_SEED_ENTROPY: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/identity-seed-entropy");
