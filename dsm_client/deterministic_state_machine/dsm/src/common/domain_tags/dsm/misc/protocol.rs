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
/// Content digest of a frozen publication artifact (exact bytes replayed to a
/// storage quorum): `H(tag ‖ 0x00 ‖ object_key ‖ 0x00 ‖ payload)`.
pub const TAG_DSM_FROZEN_ARTIFACT_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/frozen-artifact/v1");
pub const TAG_DSM_OP_VERIFY: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/op-verify");
pub const TAG_DSM_PRE_FINALIZATION: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/pre-finalization");
pub const TAG_DSM_PROOF_ROOT: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/proof-root");
pub const TAG_DSM_PROTOCOL_TRANSITION: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/protocol-transition");
pub const TAG_DSM_RECEIPT: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/receipt");
pub const TAG_DSM_RECEIPT_BIND_SESSION: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/receipt-bind-session");
/// The deterministic `x` a vault close claims its parent slot with:
/// `H(tag ‖ 0x00 ‖ vault_id ‖ parent_be ‖ owner_devid)` — so a retry produces
/// the same slot occupant rather than a second one.
pub const TAG_DSM_DLV_CLOSE_X: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/dlv-close-x");
/// The close commitment a terminal pointer names as its expected receipt:
/// `H(tag ‖ 0x00 ‖ vault_id ‖ parent_be)`.
pub const TAG_DSM_DLV_CLOSE_COMMIT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/dlv-close-commit");
/// Settlement-slot claim: the signed preimage `H(tag ‖ 0x00 ‖ canonical
/// SettlementSlotClaimBodyV1 bytes)`, and (with `-envelope`) the digest of the
/// frozen envelope bytes a register member stores and compares.
pub const TAG_DSM_SETTLEMENT_SLOT_CLAIM_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/settlement-slot-claim/v1");
pub const TAG_DSM_SETTLEMENT_SLOT_CLAIM_ENVELOPE_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/settlement-slot-claim-envelope/v1");
/// Canonical DLV state commitment: `c_n = H(tag ‖ 0x00 ‖ CCB(V_n))`, over the
/// `VaultStateV2` encoding of the CCB object registry (class `0x0001`).
pub const TAG_DSM_VAULT_STATE: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/vault-state");
/// The genesis lineage edge: `h_0 = H(tag ‖ 0x00 ‖ vault_id)`. Commits the
/// vault identity and nothing else — birth reserves, `S` and `q` are already
/// members of `V_0`.
pub const TAG_DSM_VAULT_STATE_PARENT_GENESIS_V2: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/vault-state-parent/genesis/v2");
/// Canonical storage-set identity: `H(tag ‖ 0x00 ‖ u32_be(count) ‖ for each
/// member id in lexicographic byte order: u32_be(len) ‖ id)`.
pub const TAG_DSM_STORAGE_SET_V1: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/storage-set/v1");
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
/// The online recipient's B-side receipt response target: the standard
/// session-bound target extended with the recipient's own canonical
/// relationship pair (`b_parent_tip ‖ b_child_tip`) for the applied step, so
/// `sig_b` authenticates the pair the sender pins as the peer's head.
pub const TAG_DSM_RECEIPT_B_CANONICAL: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/receipt-b-canonical/v1");
/// Signing target of a `RelationshipFinalizedV1` certificate: the canonical
/// concatenation of its seven 32-byte fields.
pub const TAG_DSM_RELATIONSHIP_FINALIZED: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/relationship-finalized/v1");
/// Content address of a frozen `RelationshipFinalizedV1` artifact (role-separated
/// like the evidence tags above).
pub const TAG_DSM_RELATIONSHIP_FINALIZED_ARTIFACT: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/relationship-finalized-artifact/v1");
pub const TAG_DSM_SILICON_FP_V4: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/silicon_fp/v4");
pub const TAG_DSM_SMT_PROOF: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/smt-proof");
pub const TAG_DSM_SPARSE_IDX: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/sparse-idx");
pub const TAG_DSM_STATE_ENTROPY: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/state-entropy");
pub const TAG_DSM_TRANSITION: TaggedHashDomain<'static> = crate::tagged_domain!(b"DSM/transition");
pub const TAG_DSM_WAL_KEY_CTX: TaggedHashDomain<'static> =
    crate::tagged_domain!(b"DSM/wal-key-ctx");
