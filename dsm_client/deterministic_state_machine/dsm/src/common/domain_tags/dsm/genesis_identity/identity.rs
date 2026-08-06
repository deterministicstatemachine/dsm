// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: identity claim and label domains

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_IDENTITY_ANCHOR: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/identity/anchor");
pub const TAG_DSM_IDENTITY_CLAIM: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/identity/claim");
pub const TAG_DSM_IDENTITY_COMBINE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/identity-combine");
pub const TAG_DSM_IDENTITY_DID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/identity-did");
pub const TAG_DSM_IDENTITY_HASH: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/identity-hash");
pub const TAG_DSM_IDENTITY_ID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/identity-id");
pub const TAG_DSM_IDENTITY_LABEL: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/identity-label");
pub const TAG_DSM_IDENTITY_MPC_ID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/identity-mpc-id");
pub const TAG_DSM_IDENTITY_SEED_ENTROPY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/identity-seed-entropy");
