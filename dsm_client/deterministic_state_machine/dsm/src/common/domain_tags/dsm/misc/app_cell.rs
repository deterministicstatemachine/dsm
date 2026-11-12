// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: application cells (DSM Amendment A35).
//!
//! An application cell is a storage cell an application names, written once
//! by a key of the writer set its key commits. The derivations live in
//! `crate::app_cell`; this file only allocates the domains.

use crate::crypto::domain::TaggedHashDomain;

/// `ω = H(tag ‖ u32be(|W|) ‖ ⨁ (u16be(alg) ‖ u32be(|key|) ‖ key))` — the
/// writer set of an application cell, in canonical order.
pub const TAG_DSM_APP_WRITERS: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/app/writers/v1");
/// `K_app = H(tag ‖ application ‖ ω ‖ u32be(|name|) ‖ name)` — the cell an
/// application names for a writer set.
pub const TAG_DSM_APP_CELL: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/app/cell/v1");
/// `s_app = H(tag ‖ K_app)` — the seed of an application cell's route.
pub const TAG_DSM_APP_CELL_SEED: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/app/cell-seed/v1");
/// `m(p) = H(tag ‖ K_app ‖ u32be(|p|) ‖ p)` — what a writer signs to write
/// payload `p` at the cell.
pub const TAG_DSM_APP_WRITE: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/app/write/v1");
/// `step = H(tag ‖ K_app ‖ occupant bytes)` — what the next cell's name
/// commits of this cell and the write that holds it.
pub const TAG_DSM_APP_STEP: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/app/step/v1");

#[cfg(test)]
pub(crate) const APP_CELL_TAGS: &[TaggedHashDomain<'static>] = &[
    TAG_DSM_APP_WRITERS,
    TAG_DSM_APP_CELL,
    TAG_DSM_APP_CELL_SEED,
    TAG_DSM_APP_WRITE,
    TAG_DSM_APP_STEP,
];
