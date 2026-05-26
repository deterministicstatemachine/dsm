//! DSM namespace tags: genesis identity

pub const TAG_DSM_CONTACT_GENESIS: &str = "DSM/contact-genesis";
pub const TAG_DSM_DEVICE: &str = "DSM/device";
pub const TAG_DSM_DEVICE_ENTROPY: &str = "DSM/device-entropy";
pub const TAG_DSM_DEVICE_FINGERPRINT: &str = "DSM/device-fingerprint";
pub const TAG_DSM_DEVICE_ID_GEN: &str = "DSM/device-id-gen";
pub const TAG_DSM_DEVID: &str = "DSM/devid";
pub const TAG_DSM_ERROR_ENVELOPE_DEVICE: &str = "DSM/error-envelope/device";
pub const TAG_DSM_ERROR_ENVELOPE_GENESIS: &str = "DSM/error-envelope/genesis";
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
pub const TAG_DSM_IDENTITY_ANCHOR: &str = "DSM/identity/anchor";
pub const TAG_DSM_IDENTITY_CLAIM: &str = "DSM/identity/claim";
pub const TAG_DSM_IDENTITY_COMBINE: &str = "DSM/identity-combine";
pub const TAG_DSM_IDENTITY_DID: &str = "DSM/identity-did";
pub const TAG_DSM_IDENTITY_HASH: &str = "DSM/identity-hash";
pub const TAG_DSM_IDENTITY_ID: &str = "DSM/identity-id";
pub const TAG_DSM_IDENTITY_LABEL: &str = "DSM/identity-label";
pub const TAG_DSM_IDENTITY_MPC_ID: &str = "DSM/identity-mpc-id";
pub const TAG_DSM_IDENTITY_SEED_ENTROPY: &str = "DSM/identity-seed-entropy";
pub const TAG_DSM_LOCAL_ID: &str = "DSM/local-id";
pub const TAG_DSM_MANIFOLD_SEED: &str = "DSM/manifold-seed";
pub const TAG_DSM_SUB_GENESIS_DEVICE_ENTROPY: &str = "DSM/sub-genesis-device-entropy";
pub const TAG_DSM_SYSTEM_FEE_DEVICE: &str = "DSM/system-fee-device";

#[cfg(test)]
pub(super) const TAGS: &[&str] = &[
    TAG_DSM_CONTACT_GENESIS,
    TAG_DSM_DEVICE,
    TAG_DSM_DEVICE_ENTROPY,
    TAG_DSM_DEVICE_FINGERPRINT,
    TAG_DSM_DEVICE_ID_GEN,
    TAG_DSM_DEVID,
    TAG_DSM_ERROR_ENVELOPE_DEVICE,
    TAG_DSM_ERROR_ENVELOPE_GENESIS,
    TAG_DSM_GENESIS,
    TAG_DSM_GENESIS_COMMIT,
    TAG_DSM_GENESIS_CONTRIB_V2,
    TAG_DSM_GENESIS_DBRW_ENV,
    TAG_DSM_GENESIS_DEVICE_COMMIT,
    TAG_DSM_GENESIS_DEVICE_ENTROPY,
    TAG_DSM_GENESIS_ENTROPY,
    TAG_DSM_GENESIS_ENTROPY_PAD,
    TAG_DSM_GENESIS_HASH,
    TAG_DSM_GENESIS_INITIAL_ENTROPY,
    TAG_DSM_GENESIS_KEYS,
    TAG_DSM_GENESIS_MERKLE,
    TAG_DSM_GENESIS_REPLAY,
    TAG_DSM_GENESIS_VERIFY,
    TAG_DSM_IDENTITY_ANCHOR,
    TAG_DSM_IDENTITY_CLAIM,
    TAG_DSM_IDENTITY_COMBINE,
    TAG_DSM_IDENTITY_DID,
    TAG_DSM_IDENTITY_HASH,
    TAG_DSM_IDENTITY_ID,
    TAG_DSM_IDENTITY_LABEL,
    TAG_DSM_IDENTITY_MPC_ID,
    TAG_DSM_IDENTITY_SEED_ENTROPY,
    TAG_DSM_LOCAL_ID,
    TAG_DSM_MANIFOLD_SEED,
    TAG_DSM_SUB_GENESIS_DEVICE_ENTROPY,
    TAG_DSM_SYSTEM_FEE_DEVICE,
];
