//! DSM namespace tags: recovery

pub const TAG_DSM_RECOVERY_ROLL: &str = "DSM/recovery-roll";
pub const TAG_DSM_RECOVERY_ROLL_PROOF: &str = "DSM/recovery-roll-proof";
pub const TAG_DSM_RECOVERY_RING: &str = "DSM/recovery-ring";
pub const TAG_DSM_RECOVERY_AEAD: &str = "DSM/recovery-aead";
pub const TAG_DSM_RECOVERY_AUTHORITY: &str = "DSM/recovery-authority";
pub const TAG_DSM_RECOVERY_NONCE: &str = "DSM/recovery-nonce";
pub const TAG_DSM_RECOVERY_CHALLENGE: &str = "DSM/recovery-challenge";
pub const TAG_DSM_RECOVERY_CAPSULE_V3: &str = "DSM/recovery-capsule-v3";
pub const TAG_DSM_TOMBSTONE: &str = "DSM/tombstone";
pub const TAG_DSM_TOMBSTONE_NOTIFY: &str = "DSM/tombstone-notify";
pub const TAG_DSM_TOMBSTONE_SUCCESSION: &str = "DSM/tombstone-succession";

#[cfg(test)]
pub(super) const TAGS: &[&str] = &[
    TAG_DSM_RECOVERY_ROLL,
    TAG_DSM_RECOVERY_ROLL_PROOF,
    TAG_DSM_RECOVERY_RING,
    TAG_DSM_RECOVERY_AEAD,
    TAG_DSM_RECOVERY_AUTHORITY,
    TAG_DSM_RECOVERY_NONCE,
    TAG_DSM_RECOVERY_CHALLENGE,
    TAG_DSM_RECOVERY_CAPSULE_V3,
    TAG_DSM_TOMBSTONE,
    TAG_DSM_TOMBSTONE_NOTIFY,
    TAG_DSM_TOMBSTONE_SUCCESSION,
];
