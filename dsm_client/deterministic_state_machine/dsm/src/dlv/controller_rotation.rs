// SPDX-License-Identifier: Apache-2.0

//! DLV controller-rotation validation (P6 keystone).
//!
//! Pure validation that a controller rotation changes ONLY the controller /
//! recovery-authority access and PRESERVES the latest verified value state — so
//! DLV controller recovery can never restore or alter a balance (spec §9). DLV
//! value lives in the DLV's own anchored chain (the latest verifiable forward
//! state), NEVER the device recovery capsule.
//!
//! Domain-separated BLAKE3; SPHINCS+ signatures. No JSON, no hex, no wall-clock.

use blake3::Hasher;

const DOMAIN_ROTATION: &[u8] = b"DSM/dlv-controller-rotation\0";
const DOMAIN_CHILD_TIP: &[u8] = b"DSM/dlv-state-tip\0";
const DOMAIN_RECOVERY_COMMIT: &[u8] = b"DSM/dlv-recovery-commit\0";

/// The latest verified DLV state the rotating verifier holds — the longest
/// verifiable forward chain it knows. A rotation is valid only against THIS tip;
/// a stale parent is rejected, so a storage node serving a stale-but-valid earlier
/// state can delay the rotation but never roll value back.
#[derive(Debug, Clone)]
pub struct DlvStateView {
    pub vault_id: [u8; 32],
    pub dlv_policy_digest: [u8; 32],
    pub current_tip: [u8; 32],
    pub value_state_commit: [u8; 32],
    pub controller_devid: [u8; 32],
    /// Commitment to the recovery authority: `BLAKE3(DOMAIN_RECOVERY_COMMIT || pk)`.
    pub recovery_commit: [u8; 32],
}

/// A controller rotation transition (typed view of `DLVControllerRotationV3`).
#[derive(Debug, Clone)]
pub struct ControllerRotation {
    pub vault_id: [u8; 32],
    pub dlv_policy_digest: [u8; 32],
    pub parent_vault_tip: [u8; 32],
    pub child_vault_tip: [u8; 32],
    pub old_controller_devid: [u8; 32],
    pub new_controller_devid: [u8; 32],
    /// The value-state commitment carried forward unchanged from the parent.
    pub latest_value_state_commit: [u8; 32],
    pub rotation_nonce: [u8; 32],
    /// SPHINCS+ signature by the recovery authority over the rotation payload.
    pub recovery_authority_proof: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RotationError {
    VaultMismatch,
    PolicyMismatch,
    /// Parent tip is not the verifier's current tip (stale / rollback attempt).
    StaleParent,
    /// `old_controller_devid` is not the active controller.
    WrongController,
    /// The rotation does not carry the current value-state commit forward.
    ValueStateDrift,
    /// The "new" controller equals the old one (not a rotation).
    ControllerUnchanged,
    /// The child tip is not the canonical value-preserving child state.
    ChildTipMismatch,
    /// The supplied authority public key does not match the committed recovery authority.
    RecoveryAuthorityMismatch,
    /// SPHINCS+ signature verification failed.
    SignatureInvalid,
    /// Underlying SPHINCS+ sign call failed.
    SignFailed(String),
}

impl core::fmt::Display for RotationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use RotationError::*;
        match self {
            VaultMismatch => write!(f, "rotation vault_id does not match the latest DLV state"),
            PolicyMismatch => write!(f, "rotation dlv_policy_digest does not match"),
            StaleParent => write!(f, "rotation parent is not the current tip (stale/rollback)"),
            WrongController => write!(f, "old_controller_devid is not the active controller"),
            ValueStateDrift => write!(
                f,
                "rotation does not preserve the latest value-state commit"
            ),
            ControllerUnchanged => {
                write!(f, "new controller equals old controller (not a rotation)")
            }
            ChildTipMismatch => write!(
                f,
                "child tip is not the canonical value-preserving child state"
            ),
            RecoveryAuthorityMismatch => {
                write!(f, "authority public key does not match recovery_commit")
            }
            SignatureInvalid => write!(f, "recovery authority signature verification failed"),
            SignFailed(m) => write!(f, "sphincs sign failed: {m}"),
        }
    }
}

impl std::error::Error for RotationError {}

/// Commitment to a recovery-authority public key.
pub fn recovery_commit_for(authority_pubkey: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_RECOVERY_COMMIT);
    h.update(authority_pubkey);
    *h.finalize().as_bytes()
}

/// Canonical signing payload for a rotation — binds every field except the proof.
fn rotation_sign_payload(r: &ControllerRotation) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_ROTATION);
    h.update(&r.vault_id);
    h.update(&r.dlv_policy_digest);
    h.update(&r.parent_vault_tip);
    h.update(&r.child_vault_tip);
    h.update(&r.old_controller_devid);
    h.update(&r.new_controller_devid);
    h.update(&r.latest_value_state_commit);
    h.update(&r.rotation_nonce);
    *h.finalize().as_bytes()
}

/// Canonical child-state tip for a rotation that PRESERVES the value commit.
/// The value-state commit is an input here, so the only way to produce a matching
/// child tip is to carry the parent's value commit forward unchanged.
#[allow(clippy::too_many_arguments)]
pub fn expected_child_tip(
    vault_id: &[u8; 32],
    dlv_policy_digest: &[u8; 32],
    parent_tip: &[u8; 32],
    value_state_commit: &[u8; 32],
    new_controller: &[u8; 32],
    recovery_commit: &[u8; 32],
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN_CHILD_TIP);
    h.update(vault_id);
    h.update(dlv_policy_digest);
    h.update(parent_tip);
    h.update(value_state_commit);
    h.update(new_controller);
    h.update(recovery_commit);
    h.update(nonce);
    *h.finalize().as_bytes()
}

/// Validate a controller rotation against the latest verified DLV state and the
/// recovery authority's public key.
///
/// Enforces (spec §9.3): vault/policy match; `parent == current tip` (no stale
/// parent / rollback); `old_controller == current`; the value-state commit is
/// preserved (`latest_value_state_commit == latest.value_state_commit` AND the
/// child tip is the canonical value-preserving child); the controller actually
/// changes; and the recovery authority public key matches the committed
/// `recovery_commit` with a valid signature over the rotation.
///
/// **Theorem:** a valid rotation preserves `value_state_commit`, so DLV
/// controller recovery cannot roll back or alter the balance.
pub fn validate_controller_rotation(
    r: &ControllerRotation,
    latest: &DlvStateView,
    recovery_authority_pubkey: &[u8],
) -> Result<(), RotationError> {
    if r.vault_id != latest.vault_id {
        return Err(RotationError::VaultMismatch);
    }
    if r.dlv_policy_digest != latest.dlv_policy_digest {
        return Err(RotationError::PolicyMismatch);
    }
    if r.parent_vault_tip != latest.current_tip {
        return Err(RotationError::StaleParent);
    }
    if r.old_controller_devid != latest.controller_devid {
        return Err(RotationError::WrongController);
    }
    if r.latest_value_state_commit != latest.value_state_commit {
        return Err(RotationError::ValueStateDrift);
    }
    if r.new_controller_devid == r.old_controller_devid {
        return Err(RotationError::ControllerUnchanged);
    }

    // Recovery-authority binding + signature.
    if recovery_commit_for(recovery_authority_pubkey) != latest.recovery_commit {
        return Err(RotationError::RecoveryAuthorityMismatch);
    }
    let payload = rotation_sign_payload(r);
    let ok = crate::crypto::sphincs::sphincs_verify(
        recovery_authority_pubkey,
        &payload,
        &r.recovery_authority_proof,
    )
    .map_err(|_| RotationError::SignatureInvalid)?;
    if !ok {
        return Err(RotationError::SignatureInvalid);
    }

    // The child tip must be the canonical state that carries the value commit
    // forward unchanged — this is what makes "balance preserved" verifiable.
    let expected = expected_child_tip(
        &r.vault_id,
        &r.dlv_policy_digest,
        &latest.current_tip,
        &latest.value_state_commit,
        &r.new_controller_devid,
        &latest.recovery_commit,
        &r.rotation_nonce,
    );
    if r.child_vault_tip != expected {
        return Err(RotationError::ChildTipMismatch);
    }

    Ok(())
}

/// Build and sign a valid controller rotation against `latest` (used by the
/// controller during recovery and by tests). The child tip is derived to preserve
/// the value-state commit.
pub fn sign_controller_rotation(
    latest: &DlvStateView,
    new_controller_devid: &[u8; 32],
    rotation_nonce: &[u8; 32],
    authority_secret_key: &[u8],
) -> Result<ControllerRotation, RotationError> {
    let child_vault_tip = expected_child_tip(
        &latest.vault_id,
        &latest.dlv_policy_digest,
        &latest.current_tip,
        &latest.value_state_commit,
        new_controller_devid,
        &latest.recovery_commit,
        rotation_nonce,
    );
    let mut r = ControllerRotation {
        vault_id: latest.vault_id,
        dlv_policy_digest: latest.dlv_policy_digest,
        parent_vault_tip: latest.current_tip,
        child_vault_tip,
        old_controller_devid: latest.controller_devid,
        new_controller_devid: *new_controller_devid,
        latest_value_state_commit: latest.value_state_commit,
        rotation_nonce: *rotation_nonce,
        recovery_authority_proof: Vec::new(),
    };
    let payload = rotation_sign_payload(&r);
    r.recovery_authority_proof =
        crate::crypto::sphincs::sphincs_sign(authority_secret_key, &payload)
            .map_err(|e| RotationError::SignFailed(format!("{e:?}")))?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(authority_pk: &[u8]) -> DlvStateView {
        DlvStateView {
            vault_id: [0x11; 32],
            dlv_policy_digest: [0x22; 32],
            current_tip: [0x33; 32],
            value_state_commit: [0x44; 32],
            controller_devid: [0x55; 32],
            recovery_commit: recovery_commit_for(authority_pk),
        }
    }

    fn fixture() -> (DlvStateView, ControllerRotation, Vec<u8>) {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let latest = view(&pk);
        let new_controller = [0x66; 32];
        let nonce = [0x77; 32];
        let r = sign_controller_rotation(&latest, &new_controller, &nonce, &sk).expect("sign");
        (latest, r, pk)
    }

    #[test]
    fn valid_rotation_passes_and_preserves_value() {
        let (latest, r, pk) = fixture();
        validate_controller_rotation(&r, &latest, &pk).expect("valid rotation");
        // The theorem: the value-state commit is carried forward unchanged.
        assert_eq!(r.latest_value_state_commit, latest.value_state_commit);
    }

    #[test]
    fn stale_parent_rejected() {
        let (mut latest, r, pk) = fixture();
        latest.current_tip = [0xAB; 32]; // verifier advanced past the rotation's parent
        assert_eq!(
            validate_controller_rotation(&r, &latest, &pk),
            Err(RotationError::StaleParent)
        );
    }

    #[test]
    fn value_drift_rejected() {
        let (latest, mut r, pk) = fixture();
        r.latest_value_state_commit = [0xCD; 32]; // attempt to change the balance
                                                  // Signature now mismatches too, but the value-drift check fires first.
        assert_eq!(
            validate_controller_rotation(&r, &latest, &pk),
            Err(RotationError::ValueStateDrift)
        );
    }

    #[test]
    fn wrong_old_controller_rejected() {
        let (mut latest, r, pk) = fixture();
        latest.controller_devid = [0x99; 32];
        assert_eq!(
            validate_controller_rotation(&r, &latest, &pk),
            Err(RotationError::WrongController)
        );
    }

    #[test]
    fn controller_unchanged_rejected() {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let latest = view(&pk);
        // "new" controller == current controller.
        let r = sign_controller_rotation(&latest, &latest.controller_devid, &[0x77; 32], &sk)
            .expect("sign");
        assert_eq!(
            validate_controller_rotation(&r, &latest, &pk),
            Err(RotationError::ControllerUnchanged)
        );
    }

    #[test]
    fn wrong_recovery_authority_rejected() {
        let (latest, r, _pk) = fixture();
        let (other_pk, _other_sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("kp");
        assert_eq!(
            validate_controller_rotation(&r, &latest, &other_pk),
            Err(RotationError::RecoveryAuthorityMismatch)
        );
    }

    #[test]
    fn tampered_child_tip_rejected() {
        let (latest, mut r, pk) = fixture();
        r.child_vault_tip[0] ^= 0x01;
        // Signature mismatches first (child tip is in the payload).
        assert_eq!(
            validate_controller_rotation(&r, &latest, &pk),
            Err(RotationError::SignatureInvalid)
        );
    }

    #[test]
    fn tampered_signature_rejected() {
        let (latest, mut r, pk) = fixture();
        r.recovery_authority_proof[0] ^= 0x01;
        assert_eq!(
            validate_controller_rotation(&r, &latest, &pk),
            Err(RotationError::SignatureInvalid)
        );
    }

    #[test]
    fn vault_and_policy_mismatch_rejected() {
        let (latest, r, pk) = fixture();
        let mut bad_vault = latest.clone();
        bad_vault.vault_id = [0xEE; 32];
        assert_eq!(
            validate_controller_rotation(&r, &bad_vault, &pk),
            Err(RotationError::VaultMismatch)
        );
        let mut bad_policy = latest.clone();
        bad_policy.dlv_policy_digest = [0xEE; 32];
        assert_eq!(
            validate_controller_rotation(&r, &bad_policy, &pk),
            Err(RotationError::PolicyMismatch)
        );
    }
}
