//! DSM namespace tags: recovery

pub const TAG_DSM_RECOVERY_ROLL: &str = "DSM/recovery-roll";
pub const TAG_DSM_RECOVERY_ROLL_PROOF: &str = "DSM/recovery-roll-proof";
pub const TAG_DSM_TOMBSTONE: &str = "DSM/tombstone";
pub const TAG_DSM_TOMBSTONE_NOTIFY: &str = "DSM/tombstone-notify";
pub const TAG_DSM_TOMBSTONE_SUCCESSION: &str = "DSM/tombstone-succession";

#[cfg(test)]
pub(super) const TAGS: &[&str] = &[
    TAG_DSM_RECOVERY_ROLL,
    TAG_DSM_RECOVERY_ROLL_PROOF,
    TAG_DSM_TOMBSTONE,
    TAG_DSM_TOMBSTONE_NOTIFY,
    TAG_DSM_TOMBSTONE_SUCCESSION,
];
