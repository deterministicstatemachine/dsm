// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: offline origin cells (proposed, DSM Amendment A39 draft).
//!
//! One cell per offline account root holds the first recognized step its owner's
//! board signed from that root. The derivations live in `crate::offline_origin`;
//! this file only allocates the domains.

use crate::crypto::domain::TaggedHashDomain;

/// `K_off = H(tag ‖ B ‖ R_off)` — the cell of the offline account root `R_off`
/// of the anchor bundle `B`.
pub const TAG_DSM_OFFLINE_ORIGIN_CELL: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/offline-origin/v1");
/// `s_off = H(tag ‖ K_off)` — the seed of an origin cell's route.
pub const TAG_DSM_OFFLINE_ORIGIN_SEED: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/offline-origin/seed/v1");

#[cfg(test)]
pub(crate) const OFFLINE_ORIGIN_TAGS: &[TaggedHashDomain<'static>] =
    &[TAG_DSM_OFFLINE_ORIGIN_CELL, TAG_DSM_OFFLINE_ORIGIN_SEED];
