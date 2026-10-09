// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: policy registry

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_CPTA: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/cpta");
pub const TAG_DSM_DISCOVERY_URL: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/discovery-url");
pub const TAG_DSM_NODE_ENDPOINT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/node-endpoint");
pub const TAG_DSM_POLICY: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/policy");
pub const TAG_DSM_REGISTRY: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/registry");
/// Key of the per-device SMT leaf that commits "this device has adopted the
/// public policy under this commit" — the authenticated fact every credit of
/// that token is checked against, so an offline receiver can verify what it
/// accepts from its own state.
pub const TAG_DSM_TOKEN_ADOPTION: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/token-adoption");

#[cfg(test)]
pub(super) const TAGS: &[TaggedHashDomain<'static>] = &[
    TAG_DSM_CPTA,
    TAG_DSM_DISCOVERY_URL,
    TAG_DSM_NODE_ENDPOINT,
    TAG_DSM_POLICY,
    TAG_DSM_REGISTRY,
    TAG_DSM_TOKEN_ADOPTION,
];
