// SPDX-License-Identifier: MIT OR Apache-2.0

//! Centralized domain tag constants for BLAKE3 domain-separated hashing.
//!
//! # NUL terminator convention (Issue #182 Finding #3 resolution)
//!
//! These constants do NOT include a trailing `\0` byte. The
//! `dsm::crypto::blake3::dsm_domain_hasher(tag)` primitive APPENDS the
//! NUL terminator automatically when constructing the BLAKE3 preimage:
//!
//! ```text
//! BLAKE3-256("DSM/<domain>\0" || data)
//! ```
//!
//! Storing the constants without the trailing NUL eliminates the
//! double-NUL footgun: a caller writing
//! `dsm_domain_hasher(TAG_RECEIPT_COMMIT)` in this convention produces
//! exactly one NUL in the preimage. Production hashing already uses
//! the non-NUL string-tag convention (for example, the `TAG_SMT_LEAF`
//! constant) — this convention now matches.
//!
//! Whitepaper alignment: §2.1 specifies `H_X(input) := BLAKE3-256(tag
//! || NUL || input)` where the NUL is part of the *primitive*, not the
//! tag identifier. So tag identifiers carried as Rust `&str` constants
//! should NOT include the NUL byte.

pub const TAG_RECEIPT_COMMIT: &str = "DSM/receipt-commit";
pub const TAG_SMT_NODE: &str = "DSM/smt-node";
pub const TAG_SMT_LEAF: &str = "DSM/smt-leaf";
pub const TAG_DBRW: &str = "DSM/dbrw";
pub const TAG_HASH_DATA: &str = "DSM/hash-data";
pub const TAG_ENTITY_ID: &str = "DSM/entity-id";
pub const TAG_DEVICE_ID: &str = "DSM/device-id";
pub const TAG_BILATERAL_SESSION: &str = "DSM/bilateral-session";
pub const TAG_SMT_KEY: &str = "DSM/smt-key";
pub const TAG_TIP: &str = "DSM/tip";
pub const TAG_STATE_HASH: &str = "DSM/state-hash";
pub const TAG_COMMITMENT: &str = "DSM/commitment";
pub const TAG_COMMITMENT_OPEN: &str = "DSM/commitment-open";
pub const TAG_COMMITMENT_FIELDS: &str = "DSM/commitment-fields";
pub const TAG_MERKLE_NODE: &str = "DSM/merkle-node";
pub const TAG_MERKLE_LEAF: &str = "DSM/merkle-leaf";
// Device Tree (standard Merkle) — see Issue #182 Finding #2 for the
// open spec ambiguity between §2.2 (`merkle-node`/`merkle-leaf`) and
// §16.3 (`dev-merkle`/`dev-empty`). Implementation continues to use
// the §16.3 ("normative") tags pending Brandon's resolution.
pub const TAG_DEV_MERKLE: &str = "DSM/dev-merkle";
pub const TAG_DEV_LEAF: &str = "DSM/dev-leaf";
pub const TAG_DEV_EMPTY: &str = "DSM/dev-empty";

/// Canonical padding leaf for odd-count Merkle levels in the Device Tree
/// (Issue #182 Finding #4 resolution). Replaces the previous self-duplication
/// pattern (`hash_node(&chunk[0], &chunk[0])`) so that a 3-device tree
/// `[A, B, C]` no longer collides with a hypothetical 4-device tree
/// `[A, B, C, C]`. Distinct domain tag from `TAG_DEV_LEAF` ensures the
/// padding leaf cannot collide with any legitimate hashed DevID.
pub const TAG_DEV_PAD: &str = "DSM/dev-tree-pad";

// `tagged_bytes()` REMOVED — Issue #182 Finding #3.
// The helper was only used in the module's own self-tests and had
// ambiguous semantics relative to the auto-NUL `dsm_domain_hasher`
// primitive. Use `dsm::crypto::blake3::dsm_domain_hasher(tag)` (or
// `domain_hash`/`domain_hash_bytes`) for all domain-separated hashing.

pub const TAG_DJTE_ACTIVE: &str = "DJTE.ACTIVE";
pub const TAG_DJTE_DLV_TIP: &str = "DJTE.DLV.TIP";
pub const TAG_DJTE_JAP: &str = "DJTE.JAP";
pub const TAG_DJTE_POLICY: &str = "DJTE.POLICY";
pub const TAG_DJTE_RCPT: &str = "DJTE.RCPT";
pub const TAG_DJTE_RESEED: &str = "DJTE.RESEED";
pub const TAG_DJTE_SEED: &str = "DJTE.SEED";
pub const TAG_DJTE_SHARD: &str = "DJTE.SHARD";
pub const TAG_DJTE_SHARDS_ROOT: &str = "DJTE.SHARDS.ROOT";
pub const TAG_DJTE_SPENT: &str = "DJTE.SPENT";
pub const TAG_DSM_AB: &str = "DSM/ab";
pub const TAG_DSM_ABC: &str = "DSM/abC";
pub const TAG_DSM_ADDR_D: &str = "DSM/addr-D";
pub const TAG_DSM_ADDR_G: &str = "DSM/addr-G";
pub const TAG_DSM_ADDR_T: &str = "DSM/addr-T";
pub const TAG_DSM_ANCHOR_TICK: &str = "DSM/anchor-tick";
pub const TAG_DSM_ATTRACTOR_COMMIT: &str = "DSM/attractor-commit";
pub const TAG_DSM_B0X: &str = "DSM/b0x";
pub const TAG_DSM_B0X_MSGID: &str = "DSM/b0x-msgid";
pub const TAG_DSM_B0X_UNILATERAL: &str = "DSM/B0X/UNILATERAL";
pub const TAG_DSM_BALANCE_ANCHOR: &str = "DSM/balance-anchor";
pub const TAG_DSM_BALANCE_COMMIT: &str = "DSM/balance-commit";
pub const TAG_DSM_BILATERAL_COMMIT: &str = "DSM/bilateral-commit";
pub const TAG_DSM_BILATERAL_ENTROPY: &str = "DSM/bilateral-entropy";
pub const TAG_DSM_BILATERAL_OP_COMMIT: &str = "DSM/bilateral-op-commit";
pub const TAG_DSM_BILATERAL_PARAMS_HASH: &str = "DSM/bilateral-params-hash";
pub const TAG_DSM_BILATERAL_STATE: &str = "DSM/bilateral-state";
pub const TAG_DSM_BITCOIN_ACCOUNT_ID: &str = "DSM/bitcoin-account-id";
pub const TAG_DSM_BLE_FRAME: &str = "DSM/ble-frame";
pub const TAG_DSM_BLE_FRAME_CHECKSUM: &str = "DSM/ble-frame-checksum";
pub const TAG_DSM_BLE_SESSION_KEY: &str = "DSM/ble-session-key";
pub const TAG_DSM_BTC_DEPOSIT_ID: &str = "DSM/btc-deposit-id";
pub const TAG_DSM_BTC_KEY_ENC: &str = "DSM/btc-key-enc";
pub const TAG_DSM_BTC_NONCE: &str = "DSM/btc-nonce";
pub const TAG_DSM_CANONICAL_BALANCE: &str = "DSM/canonical-balance";
pub const TAG_DSM_CANONICAL_LP: &str = "DSM/canonical-lp";
pub const TAG_DSM_CDBRW_BIND: &str = "DSM/cdbrw/bind";
pub const TAG_DSM_CDBRW_BINDING_RECORD: &str = "DSM/cdbrw-binding-record";
pub const TAG_DSM_CDBRW_ENTROPY: &str = "DSM/cdbrw-entropy";
pub const TAG_DSM_CDBRW_RESPONSE: &str = "DSM/cdbrw-response";
pub const TAG_DSM_CDBRW_SEED: &str = "DSM/cdbrw-seed";
pub const TAG_DSM_CDBRW_THERMAL: &str = "DSM/cdbrw-thermal";
pub const TAG_DSM_CERT_CHAIN_SK_AEAD: &str = "DSM/cert-chain-sk-aead";
pub const TAG_DSM_CHAIN_TIP: &str = "DSM/CHAIN_TIP";
pub const TAG_DSM_CHAIN_TIP_ID: &str = "DSM/chain-tip-id";
pub const TAG_DSM_CODEC_HASH: &str = "DSM/codec-hash";
pub const TAG_DSM_COMBINE_HASHES: &str = "DSM/combine-hashes";
pub const TAG_DSM_CONTACT_ADD: &str = "DSM/contact/add";
pub const TAG_DSM_CONTACT_ADD_NUL: &str = "DSM/contact/add\0";
pub const TAG_DSM_CONTACT_GENESIS: &str = "DSM/contact-genesis";
pub const TAG_DSM_COUNTERPARTY_ID: &str = "DSM/counterparty-id";
pub const TAG_DSM_CPTA: &str = "DSM/cpta";
pub const TAG_DSM_DBRW_BINDING_V2: &str = "DSM/DBRW/BINDING/v2";
pub const TAG_DSM_DBRW_COMMIT_COND: &str = "DSM/dbrw-commit-cond";
pub const TAG_DSM_DBRW_COMMIT_RECUR: &str = "DSM/dbrw-commit-recur";
pub const TAG_DSM_DBRW_COMMIT_TIMELOCK: &str = "DSM/dbrw-commit-timelock";
pub const TAG_DSM_DBRW_RWP_SEED: &str = "DSM/dbrw-rwp-seed";
pub const TAG_DSM_DBRW_RWP_STEP: &str = "DSM/dbrw-rwp-step";
pub const TAG_DSM_DBTC_BEARER_ETA: &str = "DSM/dbtc-bearer-eta";
pub const TAG_DSM_DBTC_CLAIM: &str = "DSM/dbtc-claim";
pub const TAG_DSM_DBTC_PREIMAGE: &str = "DSM/dbtc-preimage";
pub const TAG_DSM_DBTC_TEST_VAULT: &str = "DSM/dbtc-test-vault";
pub const TAG_DSM_DBTC_WITHDRAWAL_PLAN: &str = "DSM/dbtc-withdrawal-plan";
pub const TAG_DSM_DETERMINISTIC_ID: &str = "DSM/deterministic-id";
pub const TAG_DSM_DETERMINISTIC_NONCE_32: &str = "DSM/deterministic-nonce-32";
pub const TAG_DSM_DETERMINISTIC_NONCE_GCM: &str = "DSM/deterministic-nonce-gcm";
pub const TAG_DSM_DETERMINISTIC_TIME: &str = "DSM/deterministic-time";
pub const TAG_DSM_DET_RNG_SEED: &str = "DSM/det-rng-seed";
pub const TAG_DSM_DEVICE: &str = "DSM/device";
pub const TAG_DSM_DEVICE_ENTROPY: &str = "DSM/device-entropy";
pub const TAG_DSM_DEVICE_FINGERPRINT: &str = "DSM/device-fingerprint";
pub const TAG_DSM_DEVICE_ID_GEN: &str = "DSM/device-id-gen";
pub const TAG_DSM_DEVID: &str = "DSM/devid";
pub const TAG_DSM_DEV_ENT_V2: &str = "DSM/DEV_ENT/v2";
pub const TAG_DSM_DISCOVERY_URL: &str = "DSM/discovery-url";
pub const TAG_DSM_DJTE_SHARD_MERKLE: &str = "DSM/djte-shard-merkle";
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
pub const TAG_DSM_DLV_PARTITION_NUL: &str = "DSM/dlv-partition\0";
pub const TAG_DSM_DLV_POLICY: &str = "DSM/dlv-policy";
pub const TAG_DSM_DLV_PROOF: &str = "DSM/dlv-proof";
pub const TAG_DSM_DLV_REFUND: &str = "DSM/dlv-refund";
pub const TAG_DSM_DLV_UNLOCK: &str = "DSM/dlv-unlock";
pub const TAG_DSM_DLV_VAULT_ID: &str = "DSM/dlv-vault-id";
pub const TAG_DSM_EK: &str = "DSM/ek";
pub const TAG_DSM_EK_CERT: &str = "DSM/ek-cert";
pub const TAG_DSM_ENVELOPE_ID: &str = "DSM/ENVELOPE_ID";
pub const TAG_DSM_ENVELOPE_MSGID: &str = "DSM/envelope-msgid";
pub const TAG_DSM_ERROR_ENVELOPE: &str = "DSM/error-envelope";
pub const TAG_DSM_ERROR_ENVELOPE_CHAIN: &str = "DSM/error-envelope/chain";
pub const TAG_DSM_ERROR_ENVELOPE_DEVICE: &str = "DSM/error-envelope/device";
pub const TAG_DSM_ERROR_ENVELOPE_GENESIS: &str = "DSM/error-envelope/genesis";
pub const TAG_DSM_EXTERNAL_COMMIT_HASH: &str = "DSM/external-commit-hash";
pub const TAG_DSM_EXTERNAL_COMMIT_ID: &str = "DSM/external-commit-id";
pub const TAG_DSM_EXTERNAL_EVIDENCE: &str = "DSM/external-evidence";
pub const TAG_DSM_EXTERNAL_SOURCE_ID: &str = "DSM/external-source-id";
pub const TAG_DSM_FAUCET_CLAIM: &str = "DSM/faucet-claim";
pub const TAG_DSM_FLC_HASH_V2: &str = "DSM/flc/hash/v2";
pub const TAG_DSM_GENESIS: &str = "DSM/genesis";
pub const TAG_DSM_GENESIS_COMMIT: &str = "DSM/genesis-commit";
pub const TAG_DSM_GENESIS_CONTRIB_V2: &str = "DSM/GENESIS/CONTRIB/v2";
pub const TAG_DSM_GENESIS_DBRW_ENV: &str = "DSM/genesis/dbrw-env";
pub const TAG_DSM_GENESIS_DEVICE_COMMIT: &str = "DSM/genesis-device-commit";
pub const TAG_DSM_GENESIS_DEVICE_ENTROPY: &str = "DSM/genesis-device-entropy";
pub const TAG_DSM_GENESIS_ENTROPY: &str = "DSM/genesis-entropy";
pub const TAG_DSM_GENESIS_ENTROPY_PAD: &str = "DSM/genesis-entropy-pad";
pub const TAG_DSM_GENESIS_HASH: &str = "DSM/genesis-hash";
pub const TAG_DSM_GENESIS_INITIAL_ENTROPY: &str = "DSM/genesis-initial-entropy";
pub const TAG_DSM_GENESIS_KEYS: &str = "DSM/genesis/keys";
pub const TAG_DSM_GENESIS_MERKLE: &str = "DSM/genesis-merkle";
pub const TAG_DSM_GENESIS_REPLAY: &str = "DSM/genesis-replay";
pub const TAG_DSM_GENESIS_VERIFY: &str = "DSM/genesis-verify";
pub const TAG_DSM_HASH_MULTIPLE: &str = "DSM/hash-multiple";
pub const TAG_DSM_HW_FINGERPRINT: &str = "DSM/hw-fingerprint";
pub const TAG_DSM_IDENTITY_ANCHOR: &str = "DSM/identity/anchor";
pub const TAG_DSM_IDENTITY_CLAIM: &str = "DSM/identity/claim";
pub const TAG_DSM_IDENTITY_COMBINE: &str = "DSM/identity-combine";
pub const TAG_DSM_IDENTITY_DID: &str = "DSM/identity-did";
pub const TAG_DSM_IDENTITY_HASH: &str = "DSM/identity-hash";
pub const TAG_DSM_IDENTITY_ID: &str = "DSM/identity-id";
pub const TAG_DSM_IDENTITY_LABEL: &str = "DSM/identity-label";
pub const TAG_DSM_IDENTITY_MPC_ID: &str = "DSM/identity-mpc-id";
pub const TAG_DSM_IDENTITY_SEED_ENTROPY: &str = "DSM/identity-seed-entropy";
pub const TAG_DSM_JNI_CORE_ENVELOPE_MESSAGE_ID_V1: &str = "DSM/jni-core-envelope-message-id/v1";
pub const TAG_DSM_JNI_ENVELOPE_MESSAGE_ID_V1: &str = "DSM/jni-envelope-message-id/v1";
pub const TAG_DSM_KYBER_COINS: &str = "DSM/kyber-coins";
pub const TAG_DSM_KYBER_SS: &str = "DSM/kyber-ss";
pub const TAG_DSM_LOCAL_ID: &str = "DSM/local-id";
pub const TAG_DSM_MANIFOLD_SEED: &str = "DSM/manifold-seed";
pub const TAG_DSM_MERKLE_PATH: &str = "DSM/merkle-path";
pub const TAG_DSM_ML_KEM_KEYGEN_D: &str = "DSM/ml-kem-keygen-d";
pub const TAG_DSM_ML_KEM_KEYGEN_Z: &str = "DSM/ml-kem-keygen-z";
pub const TAG_DSM_ML_KEM_SEED: &str = "DSM/ml-kem-seed";
pub const TAG_DSM_MOMENT: &str = "DSM/moment";
pub const TAG_DSM_MOMENT_NODE: &str = "DSM/moment-node";
pub const TAG_DSM_NETWORK_HASH: &str = "DSM/network-hash";
pub const TAG_DSM_NEXT_ENTROPY: &str = "DSM/next-entropy";
pub const TAG_DSM_NODE_ENDPOINT: &str = "DSM/node-endpoint";
pub const TAG_DSM_NONCE: &str = "DSM/nonce";
pub const TAG_DSM_OFFLINE_KEY_CTX: &str = "DSM/offline-key-ctx";
pub const TAG_DSM_OFFLINE_TX_CTX: &str = "DSM/offline-tx-ctx";
pub const TAG_DSM_ONLINETRANSFERREQUEST_NONCE_V1: &str = "DSM/OnlineTransferRequest/nonce/v1";
pub const TAG_DSM_ONLINE_MESSAGE_NONCE_V3: &str = "DSM/online-message/nonce/v3";
pub const TAG_DSM_ONLINE_MESSAGE_V3: &str = "DSM/online-message/v3";
pub const TAG_DSM_OP_VERIFY: &str = "DSM/op-verify";
pub const TAG_DSM_PAYLOAD_DIGEST: &str = "DSM/payload-digest";
pub const TAG_DSM_PBT_VALID_STATE: &str = "DSM/PBT/VALID_STATE";
pub const TAG_DSM_PK_HASH: &str = "DSM/pk-hash";
pub const TAG_DSM_POLICY: &str = "DSM/policy";
pub const TAG_DSM_PRECOMMIT_INVALIDATION_PROOF_V2: &str = "DSM/precommit/invalidation-proof/v2";
pub const TAG_DSM_PRE_FINALIZATION: &str = "DSM/pre-finalization";
pub const TAG_DSM_PROOF_ROOT: &str = "DSM/proof-root";
pub const TAG_DSM_PROTOCOL_TRANSITION: &str = "DSM/protocol-transition";
pub const TAG_DSM_RANDOM_WALK_SEED: &str = "DSM/random-walk-seed";
pub const TAG_DSM_RECEIPT: &str = "DSM/receipt";
pub const TAG_DSM_RECEIPT_BIND_SESSION: &str = "DSM/receipt-bind-session";
pub const TAG_DSM_RECOVERY_ROLL: &str = "DSM/recovery-roll";
pub const TAG_DSM_RECOVERY_ROLL_PROOF: &str = "DSM/recovery-roll-proof";
pub const TAG_DSM_REGISTRY: &str = "DSM/registry";
pub const TAG_DSM_RELATIONSHIP: &str = "DSM/relationship";
pub const TAG_DSM_RELATIONSHIP_KEY: &str = "DSM/relationship-key";
pub const TAG_DSM_RELKEY_V2: &str = "DSM/RELKEY/v2";
pub const TAG_DSM_REQUEST_HASH: &str = "DSM/request-hash";
pub const TAG_DSM_SCRIPT_COMMIT: &str = "DSM/script-commit";
pub const TAG_DSM_SDK_BILATERAL_ENTRY_V1: &str = "DSM/sdk/bilateral-entry/v1";
pub const TAG_DSM_SDK_HASH: &str = "DSM/sdk-hash";
pub const TAG_DSM_SIGNING_PREIMAGE: &str = "DSM/signing-preimage";
pub const TAG_DSM_SILICON_FP_V4: &str = "DSM/silicon_fp/v4";
pub const TAG_DSM_SMART_COMMIT: &str = "DSM/smart-commit";
pub const TAG_DSM_SMART_COMMIT_CONDITION: &str = "DSM/smart-commit-condition";
pub const TAG_DSM_SMART_COMMIT_EVAL: &str = "DSM/smart-commit-eval";
pub const TAG_DSM_SMART_COMMIT_EVIDENCE: &str = "DSM/smart-commit-evidence";
pub const TAG_DSM_SMART_COMMIT_HASH: &str = "DSM/smart-commit-hash";
pub const TAG_DSM_SMART_COMMIT_HASH_V2: &str = "DSM/smart-commit/hash/v2";
pub const TAG_DSM_SMART_COMMIT_ID_V2: &str = "DSM/smart-commit/id/v2";
pub const TAG_DSM_SMART_COMMIT_NONCE_V2: &str = "DSM/smart-commit/nonce/v2";
pub const TAG_DSM_SMART_COMMIT_PREDICATE: &str = "DSM/smart-commit-predicate";
pub const TAG_DSM_SMT_PROOF: &str = "DSM/smt-proof";
pub const TAG_DSM_SPARSE_IDX: &str = "DSM/sparse-idx";
pub const TAG_DSM_SPHINCS_KDF: &str = "DSM/sphincs-kdf";
pub const TAG_DSM_SPHINCS_SEED: &str = "DSM/sphincs-seed";
pub const TAG_DSM_STATE_ENTROPY: &str = "DSM/state-entropy";
pub const TAG_DSM_STEP_SALT: &str = "DSM/step-salt";
pub const TAG_DSM_STREAM_CHUNK: &str = "DSM/stream-chunk";
pub const TAG_DSM_SUB_GENESIS_DEVICE_ENTROPY: &str = "DSM/sub-genesis-device-entropy";
pub const TAG_DSM_SYSTEM_FEE_DEVICE: &str = "DSM/system-fee-device";
pub const TAG_DSM_SYSTEM_OWNER: &str = "DSM/system-owner";
pub const TAG_DSM_SYSTEM_PEER_TIP: &str = "DSM/system-peer-tip";
pub const TAG_DSM_SYSTEM_PEER_TRANSITION: &str = "DSM/system-peer-transition";
pub const TAG_DSM_TAG1: &str = "DSM/tag1";
pub const TAG_DSM_TAG2: &str = "DSM/tag2";
pub const TAG_DSM_TEST: &str = "DSM/test";
pub const TAG_DSM_TEST_CSPRNG_NEXT: &str = "DSM/test-csprng-next";
pub const TAG_DSM_TEST_CSPRNG_SEED: &str = "DSM/test-csprng-seed";
pub const TAG_DSM_TEST_ENTITY_ID: &str = "DSM/test-entity-id";
pub const TAG_DSM_TEST_ENTROPY: &str = "DSM/test-entropy";
pub const TAG_DSM_TLS_CERT_HASH: &str = "DSM/tls-cert-hash";
pub const TAG_DSM_TOKEN_FACTORY: &str = "DSM/token-factory";
pub const TAG_DSM_TOKEN_HASH: &str = "DSM/token-hash";
pub const TAG_DSM_TOKEN_ID: &str = "DSM/token-id";
pub const TAG_DSM_TOKEN_METADATA: &str = "DSM/token-metadata";
pub const TAG_DSM_TOKEN_MPC_PARTICIPANT: &str = "DSM/token-mpc/participant";
pub const TAG_DSM_TOKEN_OP: &str = "DSM/token-op";
pub const TAG_DSM_TOMBSTONE: &str = "DSM/tombstone";
pub const TAG_DSM_TOMBSTONE_NOTIFY: &str = "DSM/tombstone-notify";
pub const TAG_DSM_TOMBSTONE_SUCCESSION: &str = "DSM/tombstone-succession";
pub const TAG_DSM_TRANSFER_V3: &str = "DSM/transfer/v3";
pub const TAG_DSM_TRANSITION: &str = "DSM/transition";
pub const TAG_DSM_TX_HASH: &str = "DSM/tx-hash";
pub const TAG_DSM_VAULT_AD: &str = "DSM/vault-ad";
pub const TAG_DSM_VAULT_COMMITMENT_V2: &str = "DSM/vault-commitment-v2";
pub const TAG_DSM_VAULT_ENVELOPE_V2: &str = "DSM/vault-envelope-v2";
pub const TAG_DSM_VAULT_KEK_V2: &str = "DSM/Vault/KEK/v2";
pub const TAG_DSM_VAULT_KEY_TYPE: &str = "DSM/vault-key-type";
pub const TAG_DSM_VAULT_NONCE_V2: &str = "DSM/Vault/Nonce/v2";
pub const TAG_DSM_VERIFICATION_SEED: &str = "DSM/verification-seed";
pub const TAG_DSM_WALK_SEED: &str = "DSM/walk-seed";
pub const TAG_DSM_WALK_STEP: &str = "DSM/walk-step";
pub const TAG_DSM_WAL_KEY_CTX: &str = "DSM/wal-key-ctx";
pub const TAG_DSM_WITHDRAWAL: &str = "DSM/withdrawal";
pub const TAG_NOT_DSM: &str = "not-dsm";

pub const TAG_DSM_BENCH: &str = "DSM/bench";
pub const TAG_DSM_PRECOMMIT: &str = "DSM/precommit";
pub const TAG_DSM_TAG: &str = "DSM/tag";
pub const TAG_DSM_TAG_A: &str = "DSM/tag-a";
pub const TAG_DSM_TAG_B: &str = "DSM/tag-b";
pub const TAG_DSM_TEST_CHILD: &str = "DSM/test-child";
pub const TAG_DSM_TEST_COMMIT: &str = "DSM/test-commit";
pub const TAG_DSM_TEST_DEVICE: &str = "DSM/test-device";
pub const TAG_DSM_TEST_NEXT_TIP: &str = "DSM/test-next-tip";
pub const TAG_DSM_TEST_PARENT: &str = "DSM/test-parent";
pub const TAG_DSM_TEST_TIP: &str = "DSM/test-tip";
pub const TAG_DSM_TRACE_DEVICE: &str = "DSM/trace-device";
pub const TAG_DSM_TRACE_GENESIS: &str = "DSM/trace-genesis";

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Tags MUST NOT include the trailing NUL — the hasher primitive
    /// appends it. See module docs for the convention rationale.
    #[test]
    fn all_tags_have_no_trailing_nul() {
        let tags = [
            TAG_RECEIPT_COMMIT,
            TAG_SMT_NODE,
            TAG_SMT_LEAF,
            TAG_DBRW,
            TAG_HASH_DATA,
            TAG_ENTITY_ID,
            TAG_DEVICE_ID,
            TAG_BILATERAL_SESSION,
            TAG_SMT_KEY,
            TAG_TIP,
            TAG_STATE_HASH,
            TAG_COMMITMENT,
            TAG_COMMITMENT_OPEN,
            TAG_COMMITMENT_FIELDS,
            TAG_MERKLE_NODE,
            TAG_MERKLE_LEAF,
            TAG_DEV_MERKLE,
            TAG_DEV_LEAF,
            TAG_DEV_EMPTY,
            TAG_DEV_PAD,
        ];
        for tag in &tags {
            assert!(
                !tag.ends_with('\0'),
                "Tag {tag:?} must NOT be NUL-terminated; the hasher appends NUL"
            );
            assert!(!tag.is_empty(), "Tag must not be empty");
        }
    }

    #[test]
    fn all_tags_are_unique() {
        let tags = [
            TAG_RECEIPT_COMMIT,
            TAG_SMT_NODE,
            TAG_SMT_LEAF,
            TAG_DBRW,
            TAG_HASH_DATA,
            TAG_ENTITY_ID,
            TAG_DEVICE_ID,
            TAG_BILATERAL_SESSION,
            TAG_SMT_KEY,
            TAG_TIP,
            TAG_STATE_HASH,
            TAG_COMMITMENT,
            TAG_COMMITMENT_OPEN,
            TAG_COMMITMENT_FIELDS,
            TAG_MERKLE_NODE,
            TAG_MERKLE_LEAF,
            TAG_DEV_MERKLE,
            TAG_DEV_LEAF,
            TAG_DEV_EMPTY,
            TAG_DEV_PAD,
        ];
        let set: HashSet<&str> = tags.iter().copied().collect();
        assert_eq!(set.len(), tags.len(), "All domain tags must be unique");
    }

    #[test]
    fn all_tags_start_with_dsm_prefix() {
        let tags = [
            TAG_RECEIPT_COMMIT,
            TAG_SMT_NODE,
            TAG_SMT_LEAF,
            TAG_DBRW,
            TAG_HASH_DATA,
            TAG_ENTITY_ID,
            TAG_DEVICE_ID,
            TAG_BILATERAL_SESSION,
            TAG_SMT_KEY,
            TAG_TIP,
            TAG_STATE_HASH,
            TAG_COMMITMENT,
            TAG_COMMITMENT_OPEN,
            TAG_COMMITMENT_FIELDS,
            TAG_MERKLE_NODE,
            TAG_MERKLE_LEAF,
            TAG_DEV_MERKLE,
            TAG_DEV_LEAF,
            TAG_DEV_EMPTY,
            TAG_DEV_PAD,
        ];
        for tag in &tags {
            assert!(tag.starts_with("DSM/"), "Tag {tag:?} must start with DSM/");
        }
    }
}
