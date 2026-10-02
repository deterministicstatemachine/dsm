// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: nonce and randomness domains

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_BTC_NONCE: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/btc-nonce");
pub const TAG_DSM_DETERMINISTIC_NONCE_32: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/deterministic-nonce-32");
pub const TAG_DSM_DETERMINISTIC_NONCE_GCM: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/deterministic-nonce-gcm");
pub const TAG_DSM_NONCE: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/nonce");
/// A transfer nonce as it is spent: `H(tag ‖ relationship_key ‖ nonce)`. A
/// nonce is unique within the relationship that carries it, so a transfer of
/// another relationship cannot spend it.
pub const TAG_DSM_RELATIONSHIP_NONCE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/relationship-nonce/v1");
pub const TAG_DSM_WALK_SEED: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/walk-seed");
pub const TAG_DSM_WALK_STEP: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/walk-step");
