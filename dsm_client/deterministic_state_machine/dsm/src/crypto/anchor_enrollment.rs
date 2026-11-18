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

/// A board's stamp as a disclosure carries it, and the stamp keys it is checked
/// under (DSM Amendment A38): the owner's, compiled into the wallet.
#[derive(Clone, Copy, Debug)]
pub struct StampCheck<'a> {
    /// The stamp the disclosure carries; empty when it carries none.
    pub stamp: &'a [u8],
    /// The stamp keys a stamp verifies under.
    pub keys: &'a [anchor_core::stamp::StampKey],
}

/// The board `pin` names carries the owner's stamp (DSM Amendment A38): the
/// stamp verifies under one of the stamp keys over the pin's anchor id,
/// `pk_host` and `pk_chip`. A board built and keyed by anyone else carries
/// none, and a stamp taken from another board names that board.
pub fn require_board_stamp(
    pin: &FusedAnchorPin,
    check: StampCheck<'_>,
) -> Result<(), anchor_core::stamp::StampRefusal> {
    anchor_core::stamp::verify_board_stamp::<crate::types::offline_chain::SphincsHost>(
        check.keys,
        anchor_core::stamp::BoardIdentity {
            anchor_id: &pin.anchor_id,
            pk_host: &pin.partition_pk,
            pk_chip: &pin.pk_chip,
        },
        check.stamp,
    )
}

/// What a receiver does with a sender's disclosed anchor, given what it has
/// pinned for that sender.
#[derive(Debug, PartialEq, Eq)]
pub enum PinAdmitDecision {
    /// No pin yet, the disclosed bundle recomputes for the sender, and the
    /// board carries the owner's stamp: pin the disclosed anchor.
    Admit(AnchorEnrollment),
    /// Already pinned, the disclosure matches, and the board carries the
    /// owner's stamp: keep the pin untouched.
    NoChange,
    /// The first disclosure's bundle does not recompute for the sender, or the
    /// disclosure CONFLICTS with the pinned anchor (anchor identity or bundle,
    /// policy, H0, pk_host or pk_chip). A changed anchor after pinning is a
    /// silent-substitution attack: the pinned anchor is kept, never overwritten
    /// from a transfer.
    Reject(&'static str),
    /// The board carries no stamp, or one that does not verify under the stamp
    /// keys over its identity (DSM Amendment A38). Nothing is pinned, and a
    /// pin already held is kept.
    Unstamped(anchor_core::stamp::StampRefusal),
}

/// Decide admit / no change / reject for a disclosed pin. Pure: no store, no
/// I/O. A first pin is admitted only when its bundle recomputes for the sender
/// ([`require_bundle_of`]) — from the disclosed keys, enrolled counter and
/// `birth_commitment`, the sender's pinned online key `sender_online_key`, its
/// device id and the disclosed policy: the bundle is then the one the sender's
/// online load named — and only when the board carries the owner's stamp
/// ([`require_board_stamp`], DSM Amendment A38). Against an existing pin the
/// disclosure must match it on the anchor identity and bundle, the policy,
/// `H₀`, `pk_host` and `pk_chip`, so a changed anchor is refused as changed and
/// the pin is kept (Amendment A24); a matching one must still carry the stamp,
/// so a pin held from before A38 admits nothing unstamped. Offline acceptance
/// still cannot learn of a compromise of the board found elsewhere.
pub fn pin_admit_decision(
    device_id: [u8; 32],
    sender_online_key: &[u8],
    disclosed_policy: [u8; 32],
    birth_commitment: &[u8; 32],
    disclosed: &FusedAnchorPin,
    stamp: StampCheck<'_>,
    existing: Option<&AnchorEnrollment>,
) -> PinAdmitDecision {
    let Some(cur) = existing else {
        let recomputes = require_bundle_of(
            PinKeys {
                bundle: &disclosed.bundle,
                anchor_id: &disclosed.anchor_id,
                pk_chip: &disclosed.pk_chip,
                partition_pk: &disclosed.partition_pk,
                enrolled_counter: disclosed.enrolled_counter,
            },
            BundleOwner {
                online_key: sender_online_key,
                device_id: &device_id,
                policy: &disclosed_policy,
                birth_commitment,
            },
        );
        if let Err(e) = recomputes {
            log::warn!(
                "[anchor-enrollment] a disclosed anchor whose bundle does not recompute: {e}"
            );
            return PinAdmitDecision::Reject(
                "the disclosed bundle does not recompute for the sender",
            );
        }
        if let Err(refusal) = require_board_stamp(disclosed, stamp) {
            return PinAdmitDecision::Unstamped(refusal);
        }
        return PinAdmitDecision::Admit(AnchorEnrollment {
            device_id,
            policy_hash: disclosed_policy,
            pin: disclosed.clone(),
        });
    };
    if cur.pin.anchor_id != disclosed.anchor_id || cur.pin.bundle != disclosed.bundle {
        return PinAdmitDecision::Reject("disclosed anchor identity differs from the pinned one");
    }
    if cur.policy_hash != disclosed_policy {
        return PinAdmitDecision::Reject("disclosed policy differs from the admitted one");
    }
    if cur.pin.enrolled_counter != disclosed.enrolled_counter {
        return PinAdmitDecision::Reject("disclosed H0 differs from the enrolled counter");
    }
    if cur.pin.partition_pk != disclosed.partition_pk {
        return PinAdmitDecision::Reject("disclosed pk_host differs from the pinned one");
    }
    if cur.pin.pk_chip != disclosed.pk_chip {
        return PinAdmitDecision::Reject("disclosed pk_chip differs from the pinned one");
    }
    if let Err(refusal) = require_board_stamp(&cur.pin, stamp) {
        return PinAdmitDecision::Unstamped(refusal);
    }
    PinAdmitDecision::NoChange
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

    /// The sender's pinned online key, and the birth its anchor's bundle commits.
    const ONLINE_KEY: [u8; 64] = [0x0E; 64];
    const BIRTH: [u8; 32] = [0xB7; 32];

    /// A pin whose bundle is the one an anchor born for device `0x11` under
    /// policy `0x9A` has.
    fn pin() -> FusedAnchorPin {
        FusedAnchorPin {
            bundle: anchor_core::enrollment::anchor_bundle(
                &ONLINE_KEY,
                &[0xA1; 32],
                &[0x0C; 32],
                &[0x07; 64],
                1_000_000,
                &[0x11; 32],
                &[0x9A; 32],
                &BIRTH,
            ),
            anchor_id: [0xA1; 32],
            enrolled_counter: 1_000_000,
            partition_pk: vec![0x07; 64],
            pk_chip: vec![0x0C; 32],
        }
    }

    fn pinned() -> AnchorEnrollment {
        AnchorEnrollment {
            device_id: [0x11; 32],
            policy_hash: [0x9A; 32],
            pin: pin(),
        }
    }

    use crate::crypto::sphincs::{SphincsKeyPair, SphincsVariant};
    use std::sync::OnceLock;

    /// The stamp key these tests stamp boards with: an SPX128f key from a
    /// fixed seed; the owner's own key never leaves his computer.
    fn stamp_key(seed: u8) -> SphincsKeyPair {
        crate::crypto::sphincs::generate_keypair_from_seed(SphincsVariant::SPX128f, &[seed; 32])
            .expect("an SPX128f stamp key")
    }

    fn the_stamp_key() -> &'static SphincsKeyPair {
        static KEY: OnceLock<SphincsKeyPair> = OnceLock::new();
        KEY.get_or_init(|| stamp_key(0x5A))
    }

    fn key_of(key: &SphincsKeyPair) -> anchor_core::stamp::StampKey {
        core::array::from_fn(|i| key.public_key[i])
    }

    /// The stamp keys these tests' wallet holds.
    fn stamp_keys() -> &'static [anchor_core::stamp::StampKey] {
        static KEYS: OnceLock<Vec<anchor_core::stamp::StampKey>> = OnceLock::new();
        KEYS.get_or_init(|| vec![key_of(the_stamp_key())])
    }

    /// `key`'s stamp over the board `p` names.
    fn stamp_by(key: &SphincsKeyPair, p: &FusedAnchorPin) -> Vec<u8> {
        let message = anchor_core::stamp::board_stamp_message(anchor_core::stamp::BoardIdentity {
            anchor_id: &p.anchor_id,
            pk_host: &p.partition_pk,
            pk_chip: &p.pk_chip,
        });
        crate::crypto::sphincs::sign(SphincsVariant::SPX128f, &key.secret_key, &message)
            .expect("a stamp")
    }

    /// The stamp of the board [`pin`] names, under the test stamp key.
    fn pin_stamp() -> &'static [u8] {
        static STAMP: OnceLock<Vec<u8>> = OnceLock::new();
        STAMP.get_or_init(|| stamp_by(the_stamp_key(), &pin()))
    }

    /// [`pin`]'s board, stamped.
    fn stamped() -> StampCheck<'static> {
        StampCheck {
            stamp: pin_stamp(),
            keys: stamp_keys(),
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
        assert_eq!(got.pin, pin());
        assert_eq!(got.policy_hash, [0x9A; 32]);
    }

    #[test]
    fn unadmitted_device_has_no_enrollment() {
        let store = InMemoryAnchorEnrollmentStore::new();
        assert!(store.get(&[0xABu8; 32]).is_none());
    }

    // --- receiver-admit fold: pin_admit_decision matrix ---

    /// A first disclosure whose bundle recomputes and whose board carries the
    /// owner's stamp is pinned as disclosed (DSM Amendment A38).
    #[test]
    fn pin_admit_decision_first_transfer_admits_under_disclosed_policy() {
        let d = pin();
        match pin_admit_decision(
            [0x11; 32],
            &ONLINE_KEY,
            [0x9A; 32],
            &BIRTH,
            &d,
            stamped(),
            None,
        ) {
            PinAdmitDecision::Admit(e) => {
                assert_eq!(e.device_id, [0x11; 32]);
                assert_eq!(e.policy_hash, [0x9A; 32]);
                assert_eq!(e.pin, d, "the anchor is pinned as disclosed");
            }
            other => panic!("expected Admit, got {other:?}"),
        }
    }

    /// A first disclosure is admitted only when its bundle recomputes for the
    /// sender: under another online key, another device, another policy or
    /// another birth commitment, the same bundle is not this sender's anchor.
    /// MUTATION CONTROL: admitting without the recomputation turns this red.
    #[test]
    fn a_first_disclosure_whose_bundle_does_not_recompute_is_not_admitted() {
        let d = pin();
        for (device, key, policy, birth) in [
            ([0x12; 32], ONLINE_KEY.to_vec(), [0x9A; 32], BIRTH),
            ([0x11; 32], vec![0x0F; 64], [0x9A; 32], BIRTH),
            ([0x11; 32], ONLINE_KEY.to_vec(), [0x9B; 32], BIRTH),
            ([0x11; 32], ONLINE_KEY.to_vec(), [0x9A; 32], [0xB8; 32]),
        ] {
            assert_eq!(
                pin_admit_decision(device, &key, policy, &birth, &d, stamped(), None),
                PinAdmitDecision::Reject("the disclosed bundle does not recompute for the sender"),
            );
        }
    }

    /// Every answer the decision gives, on fixed inputs: the first disclosure
    /// that recomputes is admitted as disclosed under the disclosed policy;
    /// one that does not is refused; against a pin, a match changes nothing
    /// (whatever key, device or birth the confirm names, since only a first
    /// disclosure recomputes), and each differing field is refused with its
    /// own reason, the anchor identity first.
    /// MUTATION CONTROL: dropping any one field of the comparison with the pin
    /// turns this red.
    #[test]
    fn each_disclosure_against_each_pin_state_has_one_answer() {
        let d = pin();
        let cur = pinned();
        let changed = |f: fn(&mut FusedAnchorPin)| {
            let mut c = pin();
            f(&mut c);
            c
        };

        assert_eq!(
            pin_admit_decision(
                [0x11; 32],
                &ONLINE_KEY,
                [0x9A; 32],
                &BIRTH,
                &d,
                stamped(),
                None
            ),
            PinAdmitDecision::Admit(pinned()),
        );
        assert_eq!(
            pin_admit_decision(
                [0x12; 32],
                &ONLINE_KEY,
                [0x9A; 32],
                &BIRTH,
                &d,
                stamped(),
                None
            ),
            PinAdmitDecision::Reject("the disclosed bundle does not recompute for the sender"),
        );
        assert_eq!(
            pin_admit_decision(
                [0x11; 32],
                &ONLINE_KEY,
                [0x9A; 32],
                &BIRTH,
                &d,
                stamped(),
                Some(&cur)
            ),
            PinAdmitDecision::NoChange,
        );
        assert_eq!(
            pin_admit_decision(
                [0x12; 32],
                &[0x0F; 64],
                [0x9A; 32],
                &[0xB8; 32],
                &d,
                stamped(),
                Some(&cur)
            ),
            PinAdmitDecision::NoChange,
        );
        for (disclosed, policy, reason) in [
            (
                changed(|c| c.anchor_id = [0xEE; 32]),
                [0x9A; 32],
                "disclosed anchor identity differs from the pinned one",
            ),
            (
                changed(|c| c.bundle = [0xEE; 32]),
                [0x9A; 32],
                "disclosed anchor identity differs from the pinned one",
            ),
            (
                pin(),
                [0x9B; 32],
                "disclosed policy differs from the admitted one",
            ),
            (
                changed(|c| c.enrolled_counter = 999_999),
                [0x9A; 32],
                "disclosed H0 differs from the enrolled counter",
            ),
            (
                changed(|c| c.partition_pk = vec![0x08; 64]),
                [0x9A; 32],
                "disclosed pk_host differs from the pinned one",
            ),
            (
                changed(|c| c.pk_chip = vec![0x0D; 32]),
                [0x9A; 32],
                "disclosed pk_chip differs from the pinned one",
            ),
            (
                changed(|c| {
                    c.anchor_id = [0xEE; 32];
                    c.pk_chip = vec![0x0D; 32];
                }),
                [0x9B; 32],
                "disclosed anchor identity differs from the pinned one",
            ),
        ] {
            assert_eq!(
                pin_admit_decision(
                    [0x11; 32],
                    &ONLINE_KEY,
                    policy,
                    &BIRTH,
                    &disclosed,
                    stamped(),
                    Some(&cur)
                ),
                PinAdmitDecision::Reject(reason),
                "{disclosed:?} under {policy:?}",
            );
        }
    }

    #[test]
    fn pin_admit_decision_no_change_when_disclosure_matches() {
        let cur = pinned();
        assert_eq!(
            pin_admit_decision(
                [0x11; 32],
                &ONLINE_KEY,
                [0x9A; 32],
                &BIRTH,
                &pin(),
                stamped(),
                Some(&cur)
            ),
            PinAdmitDecision::NoChange
        );
    }

    #[test]
    fn pin_admit_decision_rejects_every_conflicting_disclosure() {
        let cur = pinned();
        let base = pin();

        let mut anchor = base.clone();
        anchor.anchor_id = [0xEE; 32];
        let mut bundle = base.clone();
        bundle.bundle = [0xEE; 32];
        let mut h0 = base.clone();
        h0.enrolled_counter = 999_999;
        let mut host = base.clone();
        host.partition_pk = vec![0x08; 64];
        let mut chip = base.clone();
        chip.pk_chip = vec![0x0D; 32];

        for d in [&anchor, &bundle, &h0, &host, &chip] {
            assert!(
                matches!(
                    pin_admit_decision(
                        [0x11; 32],
                        &ONLINE_KEY,
                        [0x9A; 32],
                        &BIRTH,
                        d,
                        stamped(),
                        Some(&cur)
                    ),
                    PinAdmitDecision::Reject(_)
                ),
                "conflicting disclosure must be rejected: {d:?}"
            );
        }
        // Differing policy rejects too.
        assert!(matches!(
            pin_admit_decision(
                [0x11; 32],
                &ONLINE_KEY,
                [0x9B; 32],
                &BIRTH,
                &base,
                stamped(),
                Some(&cur)
            ),
            PinAdmitDecision::Reject(_)
        ));
    }

    /// A first disclosure is pinned only when its board carries the owner's
    /// stamp: none, a cut one, one made by another key, or one made for another
    /// board's `pk_host`, `pk_chip` or anchor id is refused as unstamped, and
    /// nothing is admitted (DSM Amendment A38).
    /// MUTATION CONTROL: admitting a first disclosure without the stamp check
    /// turns this red.
    #[test]
    fn a_first_disclosure_without_the_owners_stamp_is_not_admitted() {
        use anchor_core::stamp::StampRefusal;
        let d = pin();
        let stranger = stamp_key(0x5B);
        let other_host = FusedAnchorPin {
            partition_pk: vec![0x08; 64],
            ..pin()
        };
        let other_chip = FusedAnchorPin {
            pk_chip: vec![0x0D; 32],
            ..pin()
        };
        let other_anchor = FusedAnchorPin {
            anchor_id: [0xA2; 32],
            ..pin()
        };
        let cut = &pin_stamp()[1..];
        let by_stranger = stamp_by(&stranger, &d);
        let for_host = stamp_by(the_stamp_key(), &other_host);
        let for_chip = stamp_by(the_stamp_key(), &other_chip);
        let for_anchor = stamp_by(the_stamp_key(), &other_anchor);
        for (what, stamp, refusal) in [
            ("no stamp", &[][..], StampRefusal::Missing),
            ("a cut stamp", cut, StampRefusal::Length),
            (
                "a stamp by another key",
                &by_stranger[..],
                StampRefusal::NotStamped,
            ),
            (
                "a stamp for another pk_host",
                &for_host[..],
                StampRefusal::NotStamped,
            ),
            (
                "a stamp for another pk_chip",
                &for_chip[..],
                StampRefusal::NotStamped,
            ),
            (
                "a stamp for another anchor",
                &for_anchor[..],
                StampRefusal::NotStamped,
            ),
        ] {
            assert_eq!(
                pin_admit_decision(
                    [0x11; 32],
                    &ONLINE_KEY,
                    [0x9A; 32],
                    &BIRTH,
                    &d,
                    StampCheck {
                        stamp,
                        keys: stamp_keys(),
                    },
                    None
                ),
                PinAdmitDecision::Unstamped(refusal),
                "{what}"
            );
        }
        // The stamp key the wallet holds decides it: under the stranger's key
        // the stranger's stamp admits, and under no key nothing does.
        let strangers_keys = [key_of(&stranger)];
        assert!(matches!(
            pin_admit_decision(
                [0x11; 32],
                &ONLINE_KEY,
                [0x9A; 32],
                &BIRTH,
                &d,
                StampCheck {
                    stamp: &by_stranger,
                    keys: &strangers_keys,
                },
                None
            ),
            PinAdmitDecision::Admit(_)
        ));
        assert_eq!(
            pin_admit_decision(
                [0x11; 32],
                &ONLINE_KEY,
                [0x9A; 32],
                &BIRTH,
                &d,
                StampCheck {
                    stamp: pin_stamp(),
                    keys: &[],
                },
                None
            ),
            PinAdmitDecision::Unstamped(StampRefusal::NotStamped),
        );
    }

    /// A pin held from before Amendment A38 admits nothing unstamped: a
    /// matching disclosure without the stamp is refused as unstamped and the
    /// pin is kept; with the stamp nothing changes.
    /// MUTATION CONTROL: skipping the stamp check against an existing pin
    /// turns this red.
    #[test]
    fn a_pinned_board_still_needs_its_stamp_on_every_payment() {
        use anchor_core::stamp::StampRefusal;
        let cur = pinned();
        assert_eq!(
            pin_admit_decision(
                [0x11; 32],
                &ONLINE_KEY,
                [0x9A; 32],
                &BIRTH,
                &pin(),
                StampCheck {
                    stamp: &[],
                    keys: stamp_keys(),
                },
                Some(&cur)
            ),
            PinAdmitDecision::Unstamped(StampRefusal::Missing),
        );
        assert_eq!(
            pin_admit_decision(
                [0x11; 32],
                &ONLINE_KEY,
                [0x9A; 32],
                &BIRTH,
                &pin(),
                stamped(),
                Some(&cur)
            ),
            PinAdmitDecision::NoChange,
        );
    }

    /// Another board, stamped as it should be, is still not the pinned one: a
    /// changed anchor is refused as changed, never as unstamped, and never
    /// replaces the pin (Amendment A24's rule, kept by A38).
    #[test]
    fn a_stamped_board_never_replaces_a_pin() {
        let cur = pinned();
        let other = FusedAnchorPin {
            anchor_id: [0xA2; 32],
            ..pin()
        };
        let its_stamp = stamp_by(the_stamp_key(), &other);
        assert_eq!(
            pin_admit_decision(
                [0x11; 32],
                &ONLINE_KEY,
                [0x9A; 32],
                &BIRTH,
                &other,
                StampCheck {
                    stamp: &its_stamp,
                    keys: stamp_keys(),
                },
                Some(&cur)
            ),
            PinAdmitDecision::Reject("disclosed anchor identity differs from the pinned one"),
        );
    }
}
