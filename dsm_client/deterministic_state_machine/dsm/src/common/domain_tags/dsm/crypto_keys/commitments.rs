// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: commitment and hash domains

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_ATTRACTOR_COMMIT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/attractor-commit");
pub const TAG_DSM_BALANCE_COMMIT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/balance-commit");
pub const TAG_DSM_CODEC_HASH: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/codec-hash");
pub const TAG_DSM_EXTERNAL_COMMIT_HASH: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/external-commit-hash");
pub const TAG_DSM_EXTERNAL_COMMIT_ID: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/external-commit-id");
pub const TAG_DSM_FLC_HASH_V2: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/flc/hash/v2");
pub const TAG_DSM_MERKLE_PATH: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/merkle-path");
pub const TAG_DSM_NETWORK_HASH: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/network-hash");
pub const TAG_DSM_PAYLOAD_DIGEST: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/payload-digest");
pub const TAG_DSM_PK_HASH: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/pk-hash");
pub const TAG_DSM_PRECOMMIT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/precommit");
pub const TAG_DSM_PRECOMMIT_INVALIDATION_PROOF_V2: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/precommit/invalidation-proof/v2");
pub const TAG_DSM_REQUEST_HASH: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/request-hash");
pub const TAG_DSM_SCRIPT_COMMIT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/script-commit");
pub const TAG_DSM_SDK_HASH: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/sdk-hash");
pub const TAG_DSM_SIGNING_PREIMAGE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/signing-preimage");
pub const TAG_DSM_SMART_COMMIT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/smart-commit");
pub const TAG_DSM_SMART_COMMIT_CONDITION: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/smart-commit-condition");
pub const TAG_DSM_SMART_COMMIT_EVAL: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/smart-commit-eval");
pub const TAG_DSM_SMART_COMMIT_EVIDENCE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/smart-commit-evidence");
pub const TAG_DSM_SMART_COMMIT_HASH: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/smart-commit-hash");
pub const TAG_DSM_SMART_COMMIT_HASH_V2: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/smart-commit/hash/v2");
pub const TAG_DSM_SMART_COMMIT_ID_V2: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/smart-commit/id/v2");
pub const TAG_DSM_SMART_COMMIT_NONCE_V2: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/smart-commit/nonce/v2");
pub const TAG_DSM_SMART_COMMIT_PREDICATE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/smart-commit-predicate");
pub const TAG_DSM_TLS_CERT_HASH: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/tls-cert-hash");
pub const TAG_DSM_TOKEN_HASH: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/token-hash");
pub const TAG_DSM_TX_HASH: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/tx-hash");

/// Online transfer identity v2 — bound to (relationship_key ‖ operation_nonce).
/// v1 folded a commit height into the id, so same-amount sends in one height
/// collided; this derivation consults no clock.
pub const TAG_ONLINE_TX_ID_V2: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/online-tx-id/v2");
