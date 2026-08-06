// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: vault dbtc

use crate::crypto::domain::TaggedHashDomain;

pub const TAG_DSM_BITCOIN_ACCOUNT_ID: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/bitcoin-account-id");
pub const TAG_DSM_DBTC_BEARER_ETA: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dbtc-bearer-eta");
pub const TAG_DSM_DBTC_CLAIM: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dbtc-claim");
pub const TAG_DSM_DBTC_PREIMAGE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dbtc-preimage");
pub const TAG_DSM_DBTC_TEST_VAULT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dbtc-test-vault");
pub const TAG_DSM_DBTC_WITHDRAWAL_PLAN: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dbtc-withdrawal-plan");
pub const TAG_DSM_DLV_CHAIN_LINK: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-chain-link");
pub const TAG_DSM_DLV_CLAIM: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-claim");
pub const TAG_DSM_DLV_CONDITION: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-condition");
pub const TAG_DSM_DLV_CONTENT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-content");
pub const TAG_DSM_DLV_CONTENT_COMMIT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-content-commit");
pub const TAG_DSM_DLV_FULFILLMENT: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-fulfillment");
pub const TAG_DSM_DLV_LABEL: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-label");
pub const TAG_DSM_DLV_NONCE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-nonce");
pub const TAG_DSM_DLV_NONCE_SEED: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-nonce-seed");
pub const TAG_DSM_DLV_OPEN: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv/open");
pub const TAG_DSM_DLV_PARAMS: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-params");
pub const TAG_DSM_DLV_PARTITION: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-partition");
pub const TAG_DSM_DLV_POLICY: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-policy");
pub const TAG_DSM_DLV_PROOF: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-proof");
pub const TAG_DSM_DLV_REFUND: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-refund");
pub const TAG_DSM_DLV_UNLOCK: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-unlock");
pub const TAG_DSM_DLV_VAULT_ID: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/dlv-vault-id");
pub const TAG_DSM_VAULT_AD: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/vault-ad");
pub const TAG_DSM_VAULT_COMMITMENT_V2: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/vault-commitment-v2");
pub const TAG_DSM_VAULT_ENVELOPE_V2: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/vault-envelope-v2");
pub const TAG_DSM_VAULT_KEK_V2: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/Vault/KEK/v2");
pub const TAG_DSM_VAULT_KEY_TYPE: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/vault-key-type");
pub const TAG_DSM_VAULT_NONCE_V2: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/Vault/Nonce/v2");
pub const TAG_DSM_WITHDRAWAL: TaggedHashDomain<'static> =
    TaggedHashDomain::from_static(b"DSM/withdrawal");

#[cfg(test)]
pub(super) const TAGS: &[TaggedHashDomain<'static>] = &[
    TAG_DSM_BITCOIN_ACCOUNT_ID,
    TAG_DSM_DBTC_BEARER_ETA,
    TAG_DSM_DBTC_CLAIM,
    TAG_DSM_DBTC_PREIMAGE,
    TAG_DSM_DBTC_TEST_VAULT,
    TAG_DSM_DBTC_WITHDRAWAL_PLAN,
    TAG_DSM_DLV_CHAIN_LINK,
    TAG_DSM_DLV_CLAIM,
    TAG_DSM_DLV_CONDITION,
    TAG_DSM_DLV_CONTENT,
    TAG_DSM_DLV_CONTENT_COMMIT,
    TAG_DSM_DLV_FULFILLMENT,
    TAG_DSM_DLV_LABEL,
    TAG_DSM_DLV_NONCE,
    TAG_DSM_DLV_NONCE_SEED,
    TAG_DSM_DLV_OPEN,
    TAG_DSM_DLV_PARAMS,
    TAG_DSM_DLV_PARTITION,
    TAG_DSM_DLV_POLICY,
    TAG_DSM_DLV_PROOF,
    TAG_DSM_DLV_REFUND,
    TAG_DSM_DLV_UNLOCK,
    TAG_DSM_DLV_VAULT_ID,
    TAG_DSM_VAULT_AD,
    TAG_DSM_VAULT_COMMITMENT_V2,
    TAG_DSM_VAULT_ENVELOPE_V2,
    TAG_DSM_VAULT_KEK_V2,
    TAG_DSM_VAULT_KEY_TYPE,
    TAG_DSM_VAULT_NONCE_V2,
    TAG_DSM_WITHDRAWAL,
];
