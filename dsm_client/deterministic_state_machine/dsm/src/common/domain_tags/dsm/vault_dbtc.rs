// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM namespace tags: vault dbtc

pub const TAG_DSM_BITCOIN_ACCOUNT_ID: &str = "DSM/bitcoin-account-id";
pub const TAG_DSM_DBTC_BEARER_ETA: &str = "DSM/dbtc-bearer-eta";
pub const TAG_DSM_DBTC_CLAIM: &str = "DSM/dbtc-claim";
pub const TAG_DSM_DBTC_PREIMAGE: &str = "DSM/dbtc-preimage";
pub const TAG_DSM_DBTC_TEST_VAULT: &str = "DSM/dbtc-test-vault";
pub const TAG_DSM_DBTC_WITHDRAWAL_PLAN: &str = "DSM/dbtc-withdrawal-plan";
pub const TAG_DSM_DLV_CHAIN_LINK: &str = "DSM/dlv-chain-link";
pub const TAG_DSM_DLV_CLAIM: &str = "DSM/dlv-claim";
pub const TAG_DSM_DLV_CONDITION: &str = "DSM/dlv-condition";
pub const TAG_DSM_DLV_CONTENT: &str = "DSM/dlv-content";
pub const TAG_DSM_DLV_CONTENT_COMMIT: &str = "DSM/dlv-content-commit";
pub const TAG_DSM_DLV_FULFILLMENT: &str = "DSM/dlv-fulfillment";
pub const TAG_DSM_DLV_LABEL: &str = "DSM/dlv-label";
pub const TAG_DSM_DLV_NONCE: &str = "DSM/dlv-nonce";
pub const TAG_DSM_DLV_NONCE_SEED: &str = "DSM/dlv-nonce-seed";
pub const TAG_DSM_DLV_OPEN_NUL: &str = "DSM/dlv/open\0";
pub const TAG_DSM_DLV_PARAMS: &str = "DSM/dlv-params";
pub const TAG_DSM_DLV_PARTITION: &str = "DSM/dlv-partition";
pub const TAG_DSM_DLV_POLICY: &str = "DSM/dlv-policy";
pub const TAG_DSM_DLV_PROOF: &str = "DSM/dlv-proof";
pub const TAG_DSM_DLV_REFUND: &str = "DSM/dlv-refund";
pub const TAG_DSM_DLV_UNLOCK: &str = "DSM/dlv-unlock";
pub const TAG_DSM_DLV_VAULT_ID: &str = "DSM/dlv-vault-id";
pub const TAG_DSM_VAULT_AD: &str = "DSM/vault-ad";
pub const TAG_DSM_VAULT_COMMITMENT_V2: &str = "DSM/vault-commitment-v2";
pub const TAG_DSM_VAULT_ENVELOPE_V2: &str = "DSM/vault-envelope-v2";
pub const TAG_DSM_VAULT_KEK_V2: &str = "DSM/Vault/KEK/v2";
pub const TAG_DSM_VAULT_KEY_TYPE: &str = "DSM/vault-key-type";
pub const TAG_DSM_VAULT_NONCE_V2: &str = "DSM/Vault/Nonce/v2";
pub const TAG_DSM_WITHDRAWAL: &str = "DSM/withdrawal";

#[cfg(test)]
pub(super) const TAGS: &[&str] = &[
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
    TAG_DSM_DLV_OPEN_NUL,
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
