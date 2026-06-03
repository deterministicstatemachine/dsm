// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: policy registry

pub const TAG_DSM_CPTA: &str = "DSM/cpta";
pub const TAG_DSM_DISCOVERY_URL: &str = "DSM/discovery-url";
pub const TAG_DSM_NODE_ENDPOINT: &str = "DSM/node-endpoint";
pub const TAG_DSM_POLICY: &str = "DSM/policy";
pub const TAG_DSM_REGISTRY: &str = "DSM/registry";

#[cfg(test)]
pub(super) const TAGS: &[&str] = &[
    TAG_DSM_CPTA,
    TAG_DSM_DISCOVERY_URL,
    TAG_DSM_NODE_ENDPOINT,
    TAG_DSM_POLICY,
    TAG_DSM_REGISTRY,
];
