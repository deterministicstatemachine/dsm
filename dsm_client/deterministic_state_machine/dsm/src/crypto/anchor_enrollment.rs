// SPDX-License-Identifier: MIT OR Apache-2.0
//! Receiver-side fused-anchor enrollment — the pinned admission record for a counterparty's
//! fused anchor (Software-Authority / Hardware-Identity). Offline-bearer RECEIVER ACCEPTANCE is
//! the v2 predicate (`anchor_core::accept::accept_offline`, wired in
//! `dsm_sdk::bluetooth::anchor_accept`).
//!
//! # Why this exists
//!
//! The device-side gate only constrains what the holder's OWN device will produce; it does NOT
//! bind the RECEIVER's release-of-goods decision. The receiver-side invariant is to PIN the
//! fused anchor `{bundle B, anchor_id, enrolled_counter H₀, partition_pk, pk_chip}` at admission,
//! then accept an offline-bearer release only if it verifies under the pinned material. A
//! counterparty with no pinned fused anchor is rejected fail-closed (routes to online recovery).
//! See the project memory `finding_receiver_must_pin_anchor`.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::types::error::DsmError;

/// The fused-anchor pin for one counterparty: the values the receiver must hold to
/// recognize and verify a `dsm.anchor.OfflineRelease` (the anchor-core `VerifierContext` inputs).
/// Pinned at admission from the anchor appliance's enrollment. The `dsm_sdk` side adapts this into
/// `anchor_core::accept::PinnedAnchor` (the SDK owns that type; core does not depend on it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FusedAnchorPin {
    /// Immutable anchor bundle `B` (Def. 14).
    pub bundle: [u8; 32],
    /// Enrolled TROPIC01 anchor identity `anchor_id`.
    pub anchor_id: [u8; 32],
    /// Enrolled TROPIC01 down-counter value `H₀` (the receiver derives `u = H₀ − H`).
    pub enrolled_counter: u64,
    /// Pinned RP2350 partition public key `pk_host` (verifies `σ^host` on a release).
    pub partition_pk: Vec<u8>,
    /// Pinned resident chip Ed25519 public key `pk_chip` (verifies `σ^chip` on a release). Lives
    /// in the holder TROPIC01's ECC slot; signatures are hedged/non-deterministic, so `σ^chip` is
    /// verified but NEVER hashed into state.
    pub pk_chip: Vec<u8>,
    /// `true` iff no firmware-boundary / physical-compromise / policy event invalidates the anchor.
    pub uncompromised: bool,
}

/// What an anchor's bundle `B` binds besides its pin keys: the owner it was
/// provisioned for and its birth.
#[derive(Clone, Copy, Debug)]
pub struct BundleOwner<'a> {
    /// The owner's online key `pk_on` (`B` binds `H(pk_on)`).
    pub online_key: &'a [u8],
    /// The owner's device id.
    pub device_id: &'a [u8; 32],
    /// The policy the anchor is enrolled under.
    pub policy: &'a [u8; 32],
    /// The public birth commitment `S_birth`.
    pub birth_commitment: &'a [u8; 32],
}

/// The keys and identity an anchor's pin names beside its bundle.
#[derive(Clone, Copy, Debug)]
pub struct PinKeys<'a> {
    pub bundle: &'a [u8; 32],
    pub anchor_id: &'a [u8; 32],
    pub pk_chip: &'a [u8],
    pub partition_pk: &'a [u8],
    pub enrolled_counter: u64,
}

/// `pin`'s bundle is the anchor bundle of `owner`: `B` recomputes
/// (`anchor_core::enrollment::anchor_bundle`) from the pin's anchor id, chip
/// and partition keys and enrolled counter, and the owner's online key, device
/// id, policy and birth commitment. An anchor whose bundle binds another device,
/// another key or other pin material is not this owner's.
pub fn require_bundle_of(pin: PinKeys<'_>, owner: BundleOwner<'_>) -> Result<(), DsmError> {
    let enrolled = u32::try_from(pin.enrolled_counter)
        .map_err(|e| DsmError::invalid_operation(format!("an anchor's enrolled counter: {e}")))?;
    let recomputed = anchor_core::enrollment::anchor_bundle(
        owner.online_key,
        pin.anchor_id,
        pin.pk_chip,
        pin.partition_pk,
        enrolled,
        owner.device_id,
        owner.policy,
        owner.birth_commitment,
    );
    if recomputed != *pin.bundle {
        return Err(DsmError::invalid_operation(
            "the anchor's bundle does not recompute for its owner: it binds another device, \
             online key, policy or pin material",
        ));
    }
    Ok(())
}

/// The pinned admission record for one counterparty's fused anchor.
///
/// Filed under the counterparty's 32-byte DSM `device_id`. Populated ONLY through the normal
/// authority/admission path — never implicitly from a received release (the anti-reprovision rule:
/// a fresh self-provisioned anchor has no enrollment and is rejected).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorEnrollment {
    /// 32-byte DSM device id of the anchor holder (the key this enrollment is filed under).
    pub device_id: [u8; 32],
    /// The PINNED offline-bearer policy hash this anchor is admitted under.
    pub policy_hash: [u8; 32],
    /// The pinned fused-anchor material.
    pub pin: FusedAnchorPin,
}

/// Receiver-side store of pinned fused-anchor enrollments, keyed by counterparty `device_id`.
/// SDKs provide a persistent backing store; the in-memory impl below is the reference.
pub trait AnchorEnrollmentStore: Send + Sync {
    /// The pinned enrollment for a counterparty device, if admitted.
    fn get(&self, device_id: &[u8; 32]) -> Option<AnchorEnrollment>;

    /// Admit (pin) a fused anchor through the authority path. Overwrites any prior enrollment for
    /// the device (re-admission is an explicit authority action, never implicit from a release).
    fn admit(&self, enrollment: AnchorEnrollment) -> Result<(), DsmError>;
}

impl std::fmt::Debug for dyn AnchorEnrollmentStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnchorEnrollmentStore(..)")
    }
}

/// Reference in-memory [`AnchorEnrollmentStore`] (host wiring + tests; SDKs back it with storage).
#[derive(Default)]
pub struct InMemoryAnchorEnrollmentStore {
    enrollments: Mutex<HashMap<[u8; 32], AnchorEnrollment>>,
}

impl InMemoryAnchorEnrollmentStore {
    pub fn new() -> Self {
        Self {
            enrollments: Mutex::new(HashMap::new()),
        }
    }
}

impl std::fmt::Debug for InMemoryAnchorEnrollmentStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "InMemoryAnchorEnrollmentStore(..)")
    }
}

impl AnchorEnrollmentStore for InMemoryAnchorEnrollmentStore {
    fn get(&self, device_id: &[u8; 32]) -> Option<AnchorEnrollment> {
        self.enrollments.lock().ok()?.get(device_id).cloned()
    }

    fn admit(&self, enrollment: AnchorEnrollment) -> Result<(), DsmError> {
        self.enrollments
            .lock()
            .map_err(|_| DsmError::lock_error())?
            .insert(enrollment.device_id, enrollment);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin() -> FusedAnchorPin {
        FusedAnchorPin {
            bundle: [0xB1; 32],
            anchor_id: [0xA1; 32],
            enrolled_counter: 1000,
            partition_pk: vec![0x7; 64],
            pk_chip: vec![0xCC; 32],
            uncompromised: true,
        }
    }

    #[test]
    fn admit_then_get_returns_the_pinned_fused_anchor() {
        let store = InMemoryAnchorEnrollmentStore::new();
        let dev = [0x4u8; 32];
        assert!(store.get(&dev).is_none());
        store
            .admit(AnchorEnrollment {
                device_id: dev,
                policy_hash: [0x9A; 32],
                pin: pin(),
            })
            .expect("admit");
        let got = store.get(&dev).expect("enrolled");
        assert_eq!(got.pin.bundle, [0xB1; 32]);
        assert_eq!(got.pin.enrolled_counter, 1000);
    }

    #[test]
    fn unadmitted_device_has_no_enrollment() {
        let store = InMemoryAnchorEnrollmentStore::new();
        assert!(store.get(&[0xABu8; 32]).is_none());
    }
}
