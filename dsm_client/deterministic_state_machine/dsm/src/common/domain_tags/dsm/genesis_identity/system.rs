// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: system and envelope identity domains

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_CONTACT_GENESIS: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/contact-genesis");
pub const TAG_DSM_ERROR_ENVELOPE_DEVICE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/error-envelope/device");
pub const TAG_DSM_ERROR_ENVELOPE_GENESIS: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/error-envelope/genesis");
pub const TAG_DSM_LOCAL_ID: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/local-id");
pub const TAG_DSM_MANIFOLD_SEED: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/manifold-seed");
pub const TAG_DSM_SYSTEM_FEE_DEVICE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/system-fee-device");
