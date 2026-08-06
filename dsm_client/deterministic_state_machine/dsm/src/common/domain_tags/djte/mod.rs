// SPDX-License-Identifier: MIT OR Apache-2.0

//! DJTE-prefixed domain tags
//!
//! Domain tags under the DJTE.* namespace used by deterministic emissions logic.

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DJTE_ACTIVE: TaggedHashDomain<'static> = crate::tagged_domain!(b"DJTE.ACTIVE");
pub const TAG_DJTE_DLV_TIP: TaggedHashDomain<'static> = crate::tagged_domain!(b"DJTE.DLV.TIP");
pub const TAG_DJTE_JAP: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DJTE.JAP");
pub const TAG_DJTE_POLICY: TaggedHashDomain<'static> = crate::tagged_domain!(b"DJTE.POLICY");
pub const TAG_DJTE_RCPT: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DJTE.RCPT");
pub const TAG_DJTE_RESEED: TaggedHashDomain<'static> = crate::tagged_domain!(b"DJTE.RESEED");
pub const TAG_DJTE_SEED: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DJTE.SEED");
pub const TAG_DJTE_SHARD: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DJTE.SHARD");
pub const TAG_DJTE_SHARDS_ROOT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DJTE.SHARDS.ROOT");
pub const TAG_DJTE_SPENT: TaggedHashDomain<'static> = TaggedHashDomain::from_static(b"DJTE.SPENT");

#[cfg(test)]
pub(super) const TAGS: &[TaggedHashDomain<'static>] = &[
    TAG_DJTE_ACTIVE,
    TAG_DJTE_DLV_TIP,
    TAG_DJTE_JAP,
    TAG_DJTE_POLICY,
    TAG_DJTE_RCPT,
    TAG_DJTE_RESEED,
    TAG_DJTE_SEED,
    TAG_DJTE_SHARD,
    TAG_DJTE_SHARDS_ROOT,
    TAG_DJTE_SPENT,
];
