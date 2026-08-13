// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: protocol/state domains

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_ANCHOR_TICK: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/anchor-tick");
pub const TAG_DSM_BALANCE_ANCHOR: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/balance-anchor");
pub const TAG_DSM_CANONICAL_BALANCE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/canonical-balance");
pub const TAG_DSM_CANONICAL_LP: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/canonical-lp");
pub const TAG_DSM_DETERMINISTIC_ID: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/deterministic-id");
pub const TAG_DSM_DETERMINISTIC_TIME: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/deterministic-time");
pub const TAG_DSM_DEV_ENT_V2: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/DEV_ENT/v2");
pub const TAG_DSM_DJTE_SHARD_MERKLE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/djte-shard-merkle");
pub const TAG_DSM_OP_VERIFY: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/op-verify");
pub const TAG_DSM_PRE_FINALIZATION: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/pre-finalization");
pub const TAG_DSM_PROOF_ROOT: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/proof-root");
pub const TAG_DSM_PROTOCOL_TRANSITION: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/protocol-transition");
pub const TAG_DSM_RECEIPT: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/receipt");
pub const TAG_DSM_RECEIPT_BIND_SESSION: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/receipt-bind-session");
/// Content address of an A-side receipt-evidence artifact (ADR 0003).
///
/// Separated BY ROLE from the B-side tag below. Every evidence artifact is a
/// byte blob, so an undifferentiated `H(full_bytes)` would make an A-side
/// object, a B-side delta, and any future evidence type structurally
/// interchangeable -- a reference obtained in one role could be satisfied by an
/// object produced for another. The role is part of the identity.
pub const TAG_DSM_RECEIPT_EVIDENCE_A: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/receipt-evidence/A/v1");
/// Content address of a B-side countersign delta artifact (ADR 0003).
pub const TAG_DSM_RECEIPT_EVIDENCE_B: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/receipt-evidence/B/v1");
pub const TAG_DSM_SILICON_FP_V4: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/silicon_fp/v4");
pub const TAG_DSM_SMT_PROOF: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/smt-proof");
pub const TAG_DSM_SPARSE_IDX: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/sparse-idx");
pub const TAG_DSM_STATE_ENTROPY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/state-entropy");
pub const TAG_DSM_TRANSITION: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/transition");
pub const TAG_DSM_WAL_KEY_CTX: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/wal-key-ctx");
