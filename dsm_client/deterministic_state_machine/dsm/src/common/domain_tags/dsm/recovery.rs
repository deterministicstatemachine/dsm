// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: recovery

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_RECOVERY_ROLL: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery-roll");
pub const TAG_DSM_RECOVERY_ROLL_PROOF: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery-roll-proof");
pub const TAG_DSM_RECOVERY_NONCE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery-nonce");
pub const TAG_DSM_RECOVERY_CHALLENGE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery-challenge");
/// Domain tag for the capsule contact-set commitment (gate-set anchor, R4).
pub const TAG_DSM_RECOVERY_CONTACT_SET: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery-contact-set");
/// Domain tag for a Contact Tombstone Acknowledgement's signing bytes (P4).
pub const TAG_DSM_RECOVERY_ACK: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery-ack");
/// Domain tag for the activation seal's ack-set Merkle/root commitment (P4).
pub const TAG_DSM_RECOVERY_ACK_ROOT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery-ack-root");
/// Domain tag for the recovery activation digest (P4).
pub const TAG_DSM_RECOVERY_ACTIVATION: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery-activation");
/// Domain tag for the cross-relationship succession carry-forward commitment (§0.5).
pub const TAG_DSM_RECOVERY_CARRY_FORWARD: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery/carry-forward/v1");
/// Domain tag for the commitment to the recovery-authority public key (§0.5 step 5).
pub const TAG_DSM_RECOVERY_AUTHORITY_COMMIT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery/authority-commit/v1");
/// Domain tag for the recovery-authority anchor declaration's signing bytes (§0.5 step 5).
pub const TAG_DSM_RECOVERY_AUTHORITY_ANCHOR: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery/authority-anchor/v1");
/// Domain tag for the posted PDSMT head signing digest (§0.5 gap 13).
pub const TAG_DSM_PDSMT_HEAD: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery/pdsmt-head/v1");
/// Domain tag for a posted PDSMT leaf record's committed digest (leaf-index leaf value, §0.5 gap 13).
pub const TAG_DSM_PDSMT_LEAF: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery/pdsmt-leaf/v1");
/// Domain tag for the posted PDSMT head snapshot_id (§0.5 gap 13).
pub const TAG_DSM_PDSMT_SNAPSHOT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery/pdsmt-snapshot/v1");
/// Domain tag for the content-id of a posted relationship-chain ancestry segment (§0.5
/// Phase D prerequisite) — proves how a relationship reached its tip (h_cap ->* T_old_current).
pub const TAG_DSM_RECOVERY_REL_SEGMENT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery/rel-chain-segment/v1");
/// Domain tag for the content-id of a posted new-relationship establishment receipt (§0.5
/// Phase D prerequisite) — the (A_new,C) first state binding the carry-forward commitment.
pub const TAG_DSM_RECOVERY_ESTABLISH_RECEIPT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery/establish-receipt/v1");
/// Domain tag for the signing digest of a posted dBTC vault index (P5 dBTC enumeration) —
/// the K_A-signed list of a device's dBTC vault ids a recovering device fetches as candidates.
pub const TAG_DSM_RECOVERY_DBTC_VAULT_INDEX: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/recovery/dbtc-vault-index/v1");
pub const TAG_DSM_TOMBSTONE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/tombstone");
pub const TAG_DSM_TOMBSTONE_NOTIFY: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/tombstone-notify");
pub const TAG_DSM_TOMBSTONE_SUCCESSION: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/tombstone-succession");

#[cfg(test)]
pub(super) const TAGS: &[TaggedHashDomain<'static>] = &[
    TAG_DSM_RECOVERY_ROLL,
    TAG_DSM_RECOVERY_ROLL_PROOF,
    TAG_DSM_RECOVERY_NONCE,
    TAG_DSM_RECOVERY_CHALLENGE,
    TAG_DSM_RECOVERY_CONTACT_SET,
    TAG_DSM_RECOVERY_ACK,
    TAG_DSM_RECOVERY_ACK_ROOT,
    TAG_DSM_RECOVERY_ACTIVATION,
    TAG_DSM_RECOVERY_CARRY_FORWARD,
    TAG_DSM_RECOVERY_AUTHORITY_COMMIT,
    TAG_DSM_RECOVERY_AUTHORITY_ANCHOR,
    TAG_DSM_PDSMT_HEAD,
    TAG_DSM_PDSMT_LEAF,
    TAG_DSM_PDSMT_SNAPSHOT,
    TAG_DSM_RECOVERY_REL_SEGMENT,
    TAG_DSM_RECOVERY_ESTABLISH_RECEIPT,
    TAG_DSM_RECOVERY_DBTC_VAULT_INDEX,
    TAG_DSM_TOMBSTONE,
    TAG_DSM_TOMBSTONE_NOTIFY,
    TAG_DSM_TOMBSTONE_SUCCESSION,
];
