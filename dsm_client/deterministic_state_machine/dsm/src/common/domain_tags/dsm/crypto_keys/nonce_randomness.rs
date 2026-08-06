// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: nonce and randomness domains

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_BTC_NONCE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/btc-nonce");
pub const TAG_DSM_DETERMINISTIC_NONCE_32: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/deterministic-nonce-32");
pub const TAG_DSM_DETERMINISTIC_NONCE_GCM: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/deterministic-nonce-gcm");
pub const TAG_DSM_DET_RNG_SEED: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/det-rng-seed");
pub const TAG_DSM_NONCE: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/nonce");
pub const TAG_DSM_RANDOM_WALK_SEED: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/random-walk-seed");
pub const TAG_DSM_WALK_SEED: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/walk-seed");
pub const TAG_DSM_WALK_STEP: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/walk-step");
