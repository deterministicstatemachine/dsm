//! DSM namespace tags: misc

pub const TAG_DSM_ADDR_D: &str = "DSM/addr-D";
pub const TAG_DSM_ADDR_G: &str = "DSM/addr-G";
pub const TAG_DSM_ADDR_T: &str = "DSM/addr-T";
pub const TAG_DSM_ANCHOR_TICK: &str = "DSM/anchor-tick";
pub const TAG_DSM_BALANCE_ANCHOR: &str = "DSM/balance-anchor";
pub const TAG_DSM_BTC_DEPOSIT_ID: &str = "DSM/btc-deposit-id";
pub const TAG_DSM_BTC_KEY_ENC: &str = "DSM/btc-key-enc";
pub const TAG_DSM_CANONICAL_BALANCE: &str = "DSM/canonical-balance";
pub const TAG_DSM_CANONICAL_LP: &str = "DSM/canonical-lp";
pub const TAG_DSM_CONTACT_ADD: &str = "DSM/contact/add";
pub const TAG_DSM_CONTACT_ADD_NUL: &str = "DSM/contact/add\0";
pub const TAG_DSM_COUNTERPARTY_ID: &str = "DSM/counterparty-id";
pub const TAG_DSM_DETERMINISTIC_ID: &str = "DSM/deterministic-id";
pub const TAG_DSM_DETERMINISTIC_TIME: &str = "DSM/deterministic-time";
pub const TAG_DSM_DEV_ENT_V2: &str = "DSM/DEV_ENT/v2";
pub const TAG_DSM_DJTE_SHARD_MERKLE: &str = "DSM/djte-shard-merkle";
pub const TAG_DSM_EXTERNAL_EVIDENCE: &str = "DSM/external-evidence";
pub const TAG_DSM_EXTERNAL_SOURCE_ID: &str = "DSM/external-source-id";
pub const TAG_DSM_FAUCET_CLAIM: &str = "DSM/faucet-claim";
pub const TAG_DSM_HW_FINGERPRINT: &str = "DSM/hw-fingerprint";
pub const TAG_DSM_MOMENT: &str = "DSM/moment";
pub const TAG_DSM_MOMENT_NODE: &str = "DSM/moment-node";
pub const TAG_DSM_OP_VERIFY: &str = "DSM/op-verify";
pub const TAG_DSM_PRE_FINALIZATION: &str = "DSM/pre-finalization";
pub const TAG_DSM_PROOF_ROOT: &str = "DSM/proof-root";
pub const TAG_DSM_PROTOCOL_TRANSITION: &str = "DSM/protocol-transition";
pub const TAG_DSM_RECEIPT: &str = "DSM/receipt";
pub const TAG_DSM_RECEIPT_BIND_SESSION: &str = "DSM/receipt-bind-session";
pub const TAG_DSM_RELKEY_V2: &str = "DSM/RELKEY/v2";
pub const TAG_DSM_SILICON_FP_V4: &str = "DSM/silicon_fp/v4";
pub const TAG_DSM_SMT_PROOF: &str = "DSM/smt-proof";
pub const TAG_DSM_SPARSE_IDX: &str = "DSM/sparse-idx";
pub const TAG_DSM_STATE_ENTROPY: &str = "DSM/state-entropy";
pub const TAG_DSM_STREAM_CHUNK: &str = "DSM/stream-chunk";
pub const TAG_DSM_SYSTEM_OWNER: &str = "DSM/system-owner";
pub const TAG_DSM_TOKEN_FACTORY: &str = "DSM/token-factory";
pub const TAG_DSM_TOKEN_ID: &str = "DSM/token-id";
pub const TAG_DSM_TOKEN_METADATA: &str = "DSM/token-metadata";
pub const TAG_DSM_TOKEN_MPC_PARTICIPANT: &str = "DSM/token-mpc/participant";
pub const TAG_DSM_TOKEN_OP: &str = "DSM/token-op";
pub const TAG_DSM_TRANSITION: &str = "DSM/transition";
pub const TAG_DSM_WAL_KEY_CTX: &str = "DSM/wal-key-ctx";

// Compatibility tags retained for test/tooling code paths that still
// reference historical names.
pub const TAG_DSM_TEST: &str = "DSM/test";
pub const TAG_DSM_TEST_DEVICE: &str = "DSM/test-device";
pub const TAG_DSM_TEST_ENTITY_ID: &str = "DSM/test-entity-id";
pub const TAG_DSM_TEST_ENTROPY: &str = "DSM/test-entropy";
pub const TAG_DSM_TEST_CSPRNG_SEED: &str = "DSM/test-csprng-seed";
pub const TAG_DSM_TEST_CSPRNG_NEXT: &str = "DSM/test-csprng-next";
pub const TAG_DSM_TEST_TIP: &str = "DSM/test-tip";
pub const TAG_DSM_TEST_NEXT_TIP: &str = "DSM/test-next-tip";
pub const TAG_DSM_TEST_COMMIT: &str = "DSM/test-commit";
pub const TAG_DSM_TEST_PARENT: &str = "DSM/test-parent";
pub const TAG_DSM_TEST_CHILD: &str = "DSM/test-child";
pub const TAG_DSM_PBT_VALID_STATE: &str = "DSM/pbt-valid-state";
pub const TAG_DSM_BENCH: &str = "DSM/bench";
pub const TAG_DSM_TRACE_GENESIS: &str = "DSM/trace-genesis";
pub const TAG_DSM_TRACE_DEVICE: &str = "DSM/trace-device";
pub const TAG_DSM_AB: &str = "DSM/ab";
pub const TAG_DSM_ABC: &str = "DSM/abc";
pub const TAG_DSM_TAG: &str = "DSM/tag";
pub const TAG_DSM_TAG_A: &str = "DSM/tag-a";
pub const TAG_DSM_TAG_B: &str = "DSM/tag-b";
pub const TAG_DSM_TAG1: &str = "DSM/tag1";
pub const TAG_DSM_TAG2: &str = "DSM/tag2";

#[cfg(test)]
pub(super) const TAGS: &[&str] = &[
    TAG_DSM_ADDR_D,
    TAG_DSM_ADDR_G,
    TAG_DSM_ADDR_T,
    TAG_DSM_ANCHOR_TICK,
    TAG_DSM_BALANCE_ANCHOR,
    TAG_DSM_BTC_DEPOSIT_ID,
    TAG_DSM_BTC_KEY_ENC,
    TAG_DSM_CANONICAL_BALANCE,
    TAG_DSM_CANONICAL_LP,
    TAG_DSM_CONTACT_ADD,
    TAG_DSM_CONTACT_ADD_NUL,
    TAG_DSM_COUNTERPARTY_ID,
    TAG_DSM_DETERMINISTIC_ID,
    TAG_DSM_DETERMINISTIC_TIME,
    TAG_DSM_DEV_ENT_V2,
    TAG_DSM_DJTE_SHARD_MERKLE,
    TAG_DSM_EXTERNAL_EVIDENCE,
    TAG_DSM_EXTERNAL_SOURCE_ID,
    TAG_DSM_FAUCET_CLAIM,
    TAG_DSM_HW_FINGERPRINT,
    TAG_DSM_MOMENT,
    TAG_DSM_MOMENT_NODE,
    TAG_DSM_OP_VERIFY,
    TAG_DSM_PRE_FINALIZATION,
    TAG_DSM_PROOF_ROOT,
    TAG_DSM_PROTOCOL_TRANSITION,
    TAG_DSM_RECEIPT,
    TAG_DSM_RECEIPT_BIND_SESSION,
    TAG_DSM_RELKEY_V2,
    TAG_DSM_SILICON_FP_V4,
    TAG_DSM_SMT_PROOF,
    TAG_DSM_SPARSE_IDX,
    TAG_DSM_STATE_ENTROPY,
    TAG_DSM_STREAM_CHUNK,
    TAG_DSM_SYSTEM_OWNER,
    TAG_DSM_TOKEN_FACTORY,
    TAG_DSM_TOKEN_ID,
    TAG_DSM_TOKEN_METADATA,
    TAG_DSM_TOKEN_MPC_PARTICIPANT,
    TAG_DSM_TOKEN_OP,
    TAG_DSM_TRANSITION,
    TAG_DSM_WAL_KEY_CTX,
];
