//! DSM namespace tags: crypto keys

pub const TAG_DSM_ATTRACTOR_COMMIT: &str = "DSM/attractor-commit";
pub const TAG_DSM_BALANCE_COMMIT: &str = "DSM/balance-commit";
pub const TAG_DSM_BTC_NONCE: &str = "DSM/btc-nonce";
pub const TAG_DSM_CDBRW_BIND: &str = "DSM/cdbrw/bind";
pub const TAG_DSM_CDBRW_BINDING_RECORD: &str = "DSM/cdbrw-binding-record";
pub const TAG_DSM_CDBRW_ENTROPY: &str = "DSM/cdbrw-entropy";
pub const TAG_DSM_CDBRW_RESPONSE: &str = "DSM/cdbrw-response";
pub const TAG_DSM_CDBRW_SEED: &str = "DSM/cdbrw-seed";
pub const TAG_DSM_CDBRW_THERMAL: &str = "DSM/cdbrw-thermal";
pub const TAG_DSM_CERT_CHAIN_SK_AEAD: &str = "DSM/cert-chain-sk-aead";
pub const TAG_DSM_CODEC_HASH: &str = "DSM/codec-hash";
pub const TAG_DSM_COMBINE_HASHES: &str = "DSM/combine-hashes";
pub const TAG_DSM_DBRW_BINDING_V2: &str = "DSM/DBRW/BINDING/v2";
pub const TAG_DSM_DBRW_COMMIT_COND: &str = "DSM/dbrw-commit-cond";
pub const TAG_DSM_DBRW_COMMIT_RECUR: &str = "DSM/dbrw-commit-recur";
pub const TAG_DSM_DBRW_COMMIT_TIMELOCK: &str = "DSM/dbrw-commit-timelock";
pub const TAG_DSM_DBRW_RWP_SEED: &str = "DSM/dbrw-rwp-seed";
pub const TAG_DSM_DBRW_RWP_STEP: &str = "DSM/dbrw-rwp-step";
pub const TAG_DSM_DETERMINISTIC_NONCE_32: &str = "DSM/deterministic-nonce-32";
pub const TAG_DSM_DETERMINISTIC_NONCE_GCM: &str = "DSM/deterministic-nonce-gcm";
pub const TAG_DSM_DET_RNG_SEED: &str = "DSM/det-rng-seed";
pub const TAG_DSM_EK: &str = "DSM/ek";
pub const TAG_DSM_EK_CERT: &str = "DSM/ek-cert";
pub const TAG_DSM_EXTERNAL_COMMIT_HASH: &str = "DSM/external-commit-hash";
pub const TAG_DSM_EXTERNAL_COMMIT_ID: &str = "DSM/external-commit-id";
pub const TAG_DSM_FLC_HASH_V2: &str = "DSM/flc/hash/v2";
pub const TAG_DSM_HASH_MULTIPLE: &str = "DSM/hash-multiple";
pub const TAG_DSM_KYBER_COINS: &str = "DSM/kyber-coins";
pub const TAG_DSM_KYBER_SS: &str = "DSM/kyber-ss";
pub const TAG_DSM_MERKLE_PATH: &str = "DSM/merkle-path";
pub const TAG_DSM_ML_KEM_KEYGEN_D: &str = "DSM/ml-kem-keygen-d";
pub const TAG_DSM_ML_KEM_KEYGEN_Z: &str = "DSM/ml-kem-keygen-z";
pub const TAG_DSM_ML_KEM_SEED: &str = "DSM/ml-kem-seed";
pub const TAG_DSM_NETWORK_HASH: &str = "DSM/network-hash";
pub const TAG_DSM_NEXT_ENTROPY: &str = "DSM/next-entropy";
pub const TAG_DSM_NONCE: &str = "DSM/nonce";
pub const TAG_DSM_PAYLOAD_DIGEST: &str = "DSM/payload-digest";
pub const TAG_DSM_PK_HASH: &str = "DSM/pk-hash";
pub const TAG_DSM_PRECOMMIT: &str = "DSM/precommit";
pub const TAG_DSM_PRECOMMIT_INVALIDATION_PROOF_V2: &str = "DSM/precommit/invalidation-proof/v2";
pub const TAG_DSM_RANDOM_WALK_SEED: &str = "DSM/random-walk-seed";
pub const TAG_DSM_REQUEST_HASH: &str = "DSM/request-hash";
pub const TAG_DSM_SCRIPT_COMMIT: &str = "DSM/script-commit";
pub const TAG_DSM_SDK_HASH: &str = "DSM/sdk-hash";
pub const TAG_DSM_SIGNING_PREIMAGE: &str = "DSM/signing-preimage";
pub const TAG_DSM_SMART_COMMIT: &str = "DSM/smart-commit";
pub const TAG_DSM_SMART_COMMIT_CONDITION: &str = "DSM/smart-commit-condition";
pub const TAG_DSM_SMART_COMMIT_EVAL: &str = "DSM/smart-commit-eval";
pub const TAG_DSM_SMART_COMMIT_EVIDENCE: &str = "DSM/smart-commit-evidence";
pub const TAG_DSM_SMART_COMMIT_HASH: &str = "DSM/smart-commit-hash";
pub const TAG_DSM_SMART_COMMIT_HASH_V2: &str = "DSM/smart-commit/hash/v2";
pub const TAG_DSM_SMART_COMMIT_ID_V2: &str = "DSM/smart-commit/id/v2";
pub const TAG_DSM_SMART_COMMIT_NONCE_V2: &str = "DSM/smart-commit/nonce/v2";
pub const TAG_DSM_SMART_COMMIT_PREDICATE: &str = "DSM/smart-commit-predicate";
pub const TAG_DSM_SPHINCS_KDF: &str = "DSM/sphincs-kdf";
pub const TAG_DSM_SPHINCS_SEED: &str = "DSM/sphincs-seed";
pub const TAG_DSM_STEP_SALT: &str = "DSM/step-salt";
pub const TAG_DSM_TLS_CERT_HASH: &str = "DSM/tls-cert-hash";
pub const TAG_DSM_TOKEN_HASH: &str = "DSM/token-hash";
pub const TAG_DSM_TX_HASH: &str = "DSM/tx-hash";
pub const TAG_DSM_VERIFICATION_SEED: &str = "DSM/verification-seed";
pub const TAG_DSM_WALK_SEED: &str = "DSM/walk-seed";
pub const TAG_DSM_WALK_STEP: &str = "DSM/walk-step";

#[cfg(test)]
pub(super) const TAGS: &[&str] = &[
    TAG_DSM_ATTRACTOR_COMMIT,
    TAG_DSM_BALANCE_COMMIT,
    TAG_DSM_BTC_NONCE,
    TAG_DSM_CDBRW_BIND,
    TAG_DSM_CDBRW_BINDING_RECORD,
    TAG_DSM_CDBRW_ENTROPY,
    TAG_DSM_CDBRW_RESPONSE,
    TAG_DSM_CDBRW_SEED,
    TAG_DSM_CDBRW_THERMAL,
    TAG_DSM_CERT_CHAIN_SK_AEAD,
    TAG_DSM_CODEC_HASH,
    TAG_DSM_COMBINE_HASHES,
    TAG_DSM_DBRW_BINDING_V2,
    TAG_DSM_DBRW_COMMIT_COND,
    TAG_DSM_DBRW_COMMIT_RECUR,
    TAG_DSM_DBRW_COMMIT_TIMELOCK,
    TAG_DSM_DBRW_RWP_SEED,
    TAG_DSM_DBRW_RWP_STEP,
    TAG_DSM_DETERMINISTIC_NONCE_32,
    TAG_DSM_DETERMINISTIC_NONCE_GCM,
    TAG_DSM_DET_RNG_SEED,
    TAG_DSM_EK,
    TAG_DSM_EK_CERT,
    TAG_DSM_EXTERNAL_COMMIT_HASH,
    TAG_DSM_EXTERNAL_COMMIT_ID,
    TAG_DSM_FLC_HASH_V2,
    TAG_DSM_HASH_MULTIPLE,
    TAG_DSM_KYBER_COINS,
    TAG_DSM_KYBER_SS,
    TAG_DSM_MERKLE_PATH,
    TAG_DSM_ML_KEM_KEYGEN_D,
    TAG_DSM_ML_KEM_KEYGEN_Z,
    TAG_DSM_ML_KEM_SEED,
    TAG_DSM_NETWORK_HASH,
    TAG_DSM_NEXT_ENTROPY,
    TAG_DSM_NONCE,
    TAG_DSM_PAYLOAD_DIGEST,
    TAG_DSM_PK_HASH,
    TAG_DSM_PRECOMMIT,
    TAG_DSM_PRECOMMIT_INVALIDATION_PROOF_V2,
    TAG_DSM_RANDOM_WALK_SEED,
    TAG_DSM_REQUEST_HASH,
    TAG_DSM_SCRIPT_COMMIT,
    TAG_DSM_SDK_HASH,
    TAG_DSM_SIGNING_PREIMAGE,
    TAG_DSM_SMART_COMMIT,
    TAG_DSM_SMART_COMMIT_CONDITION,
    TAG_DSM_SMART_COMMIT_EVAL,
    TAG_DSM_SMART_COMMIT_EVIDENCE,
    TAG_DSM_SMART_COMMIT_HASH,
    TAG_DSM_SMART_COMMIT_HASH_V2,
    TAG_DSM_SMART_COMMIT_ID_V2,
    TAG_DSM_SMART_COMMIT_NONCE_V2,
    TAG_DSM_SMART_COMMIT_PREDICATE,
    TAG_DSM_SPHINCS_KDF,
    TAG_DSM_SPHINCS_SEED,
    TAG_DSM_STEP_SALT,
    TAG_DSM_TLS_CERT_HASH,
    TAG_DSM_TOKEN_HASH,
    TAG_DSM_TX_HASH,
    TAG_DSM_VERIFICATION_SEED,
    TAG_DSM_WALK_SEED,
    TAG_DSM_WALK_STEP,
];
