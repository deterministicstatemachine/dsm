// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: shared lineages (DSM Amendment A15, SoFi Amendment
//! S23). The objects live in `crate::shared_lineage`; this file only
//! allocates the domains.

use crate::crypto::domain::TaggedHashDomain;

/// `d_0 = H(tag ‖ CCB(SharedGenesisV1))`.
pub const TAG_DSM_SHARED_LINEAGE_GENESIS: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/shared-lineage/genesis/v1");
/// `d_g = H(tag ‖ CCB(SharedGenerationV1))`.
pub const TAG_DSM_SHARED_LINEAGE_GENERATION: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/shared-lineage/generation/v1");
/// A vault generation's `step_digest = H(tag ‖ E)`.
pub const TAG_DSM_SHARED_LINEAGE_VAULT_STEP: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/shared-lineage/vault-step/v1");
/// `checkpoint_digest = H(tag ‖ CCB(every other checkpoint field))`.
pub const TAG_DSM_SHARED_LINEAGE_CHECKPOINT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/shared-lineage/checkpoint/v1");
/// `lineage_epoch_locator(k, id, e) = H(tag ‖ u8 k ‖ id ‖ u64be(e))`.
pub const TAG_DSM_SHARED_LINEAGE_EPOCH_LOCATOR: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/shared-lineage/epoch-locator/v1");
/// The immutable-store namespace of a hint, a checkpoint or a bundle.
pub const TAG_DSM_SHARED_LINEAGE_OBJECT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/shared-lineage/object/v1");

#[cfg(test)]
pub(crate) const SHARED_LINEAGE_TAGS: &[TaggedHashDomain<'static>] = &[
    TAG_DSM_SHARED_LINEAGE_GENESIS,
    TAG_DSM_SHARED_LINEAGE_GENERATION,
    TAG_DSM_SHARED_LINEAGE_VAULT_STEP,
    TAG_DSM_SHARED_LINEAGE_CHECKPOINT,
    TAG_DSM_SHARED_LINEAGE_EPOCH_LOCATOR,
    TAG_DSM_SHARED_LINEAGE_OBJECT,
];
