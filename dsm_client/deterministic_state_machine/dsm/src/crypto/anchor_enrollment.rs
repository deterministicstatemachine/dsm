// SPDX-License-Identifier: MIT OR Apache-2.0
//! Receiver-side fused-anchor enrollment — the pinned admission record for a counterparty's
//! Boot Fenced Fused Anchor. Offline-bearer RECEIVER ACCEPTANCE is the fused-anchor predicate
//! (`anchor_core::accept::accept_offline`, wired in `dsm_sdk::bluetooth::anchor_accept`).
//!
//! # Why this exists
//!
//! The device-side gate only constrains what the holder's OWN device will produce; it does NOT
//! bind the RECEIVER's release-of-goods decision. The receiver-side invariant is to PIN the
//! fused anchor `{bundle B, anchor_id, enrolled_counter H₀, partition_pk}` at admission, then
//! accept an offline-bearer release only if it verifies under the pinned material. A counterparty
//! with no pinned fused anchor is rejected fail-closed (routes to online recovery). See the
//! project memory `finding_receiver_must_pin_anchor`.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::types::error::DsmError;

/// The Boot Fenced Fused Anchor pin for one counterparty: the values the receiver must hold to
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
    /// Pinned RP2350 partition public key (verifies boot tickets + the partition final cert).
    pub partition_pk: Vec<u8>,
    /// `true` iff no firmware-boundary / physical-compromise / policy event invalidates the anchor.
    pub uncompromised: bool,
    /// Path-B counter verification: the READ-ONLY verifier pairing slot index on the holder's
    /// TROPIC01 that THIS receiver's pairing key is enrolled into. The receiver opens its own
    /// authenticated L3 session to that slot (over the raw-SPI relay) and reads `H` itself. `None`
    /// until a verifier slot is provisioned for this receiver — a bearer transfer from this anchor
    /// then stays FAIL-CLOSED / online-only (no way to authenticate the counter).
    pub verifier_slot: Option<u8>,
    /// The holder chip's pinned Noise static public key (`stpub`), captured at enrollment. The
    /// receiver compares the chip's presented static key against this BEFORE trusting a counter, so
    /// the relay cannot be pointed at an attacker-substituted chip. `None` -> Path-B fail-closed.
    pub chip_static_pubkey: Option<[u8; 32]>,
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
            uncompromised: true,
            verifier_slot: Some(1),
            chip_static_pubkey: Some([0xCC; 32]),
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
