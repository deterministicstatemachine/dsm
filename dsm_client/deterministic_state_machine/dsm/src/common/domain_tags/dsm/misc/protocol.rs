// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: protocol/state domains

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_ANCHOR_TICK: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/anchor-tick");
pub const TAG_DSM_BALANCE_ANCHOR: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/balance-anchor");
pub const TAG_DSM_CANONICAL_BALANCE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/canonical-balance");
pub const TAG_DSM_CANONICAL_LP: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/canonical-lp");
pub const TAG_DSM_DETERMINISTIC_ID: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/deterministic-id");
pub const TAG_DSM_DETERMINISTIC_TIME: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/deterministic-time");
pub const TAG_DSM_DEV_ENT_V2: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/DEV_ENT/v2");
pub const TAG_DSM_DJTE_SHARD_MERKLE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/djte-shard-merkle");
pub const TAG_DSM_OP_VERIFY: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/op-verify");
pub const TAG_DSM_PRE_FINALIZATION: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/pre-finalization");
pub const TAG_DSM_PROOF_ROOT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/proof-root");
pub const TAG_DSM_PROTOCOL_TRANSITION: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/protocol-transition");
pub const TAG_DSM_RECEIPT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/receipt");
pub const TAG_DSM_RECEIPT_BIND_SESSION: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/receipt-bind-session");
pub const TAG_DSM_SILICON_FP_V4: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/silicon_fp/v4");
pub const TAG_DSM_SMT_PROOF: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/smt-proof");
pub const TAG_DSM_SPARSE_IDX: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/sparse-idx");
pub const TAG_DSM_STATE_ENTROPY: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/state-entropy");
pub const TAG_DSM_TRANSITION: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/transition");
pub const TAG_DSM_WAL_KEY_CTX: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/wal-key-ctx");
