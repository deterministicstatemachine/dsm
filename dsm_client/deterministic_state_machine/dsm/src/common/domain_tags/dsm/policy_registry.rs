// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: policy registry

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_CPTA: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/cpta");
pub const TAG_DSM_DISCOVERY_URL: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/discovery-url");
pub const TAG_DSM_NODE_ENDPOINT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/node-endpoint");
pub const TAG_DSM_POLICY: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DSM/policy");
pub const TAG_DSM_REGISTRY: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/registry");

#[cfg(test)]
pub(super) const TAGS: &[TaggedHashDomain<'static>] = &[
    TAG_DSM_CPTA,
    TAG_DSM_DISCOVERY_URL,
    TAG_DSM_NODE_ENDPOINT,
    TAG_DSM_POLICY,
    TAG_DSM_REGISTRY,
];
