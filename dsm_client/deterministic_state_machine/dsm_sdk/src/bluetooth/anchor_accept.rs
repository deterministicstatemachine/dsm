// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical offline acceptance for the bilateral RECEIVER path: the v2 Software-Authority /
//! Hardware-Identity predicate (`anchor_core::accept::accept_offline`, Def. 12).
//!
//! The DSM app supplies three adapters and NEVER reimplements anchor crypto:
//!   - [`DsmStateVerifier`] (`DsmVerifier`): device-SMT inclusion of the anchor-state leaf
//!     `L = H("DSM/anchor-state/v2" ‖ B ‖ h ‖ u)` in `R_i`/`R_{i+1}` (reuses the DSM SMT), the DSM
//!     transition (handler-gated), delivery, and the genesis upgrade cert (dormant in Stage 3).
//!   - [`Ed25519ChipSig`] (`ChipSig`): the resident-chip signature `σ^chip`, verified with the
//!     enrolled `pk_chip` via `dsm::crypto::classical_verify::verify_ed25519`.
//!   - SPHINCS+ `PartitionSig` (`σ^host`): reuses `dsm::crypto::sphincs` under the pinned `pk_host`.
//!
//! Fail-closed: an absent/malformed release, an un-enrolled anchor, or ANY failed predicate check
//! releases no value and recovers online. There is **no** live counter read, no relay, no boot
//! fence, and no MACANDD on this path — uniqueness is the software device-SMT frontier; the SMT
//! inclusion proofs `Π_i`/`Π_{i+1}` ride inside the release.

use anchor_core::accept::{accept_offline, AcceptError, DsmVerifier, VerifierContext};
use anchor_core::proto::pb;
use anchor_core::tropic::ChipSig;
use prost::Message;

use dsm::types::error::DsmError;

/// The partition (`σ^host`) scheme: BLAKE3-SPHINCS+ SPX128f, byte-compatible with `dsm::crypto::sphincs`.
const PARTITION_VARIANT: dsm::crypto::sphincs::SphincsVariant =
    dsm::crypto::sphincs::SphincsVariant::SPX128f;

/// Why an offline transfer was not accepted. Every variant means the same to the caller: release
/// no value, recover online.
#[derive(Debug)]
pub enum OfflineRecover {
    /// No canonical release on the confirm.
    MissingRelease,
    /// The release bytes did not decode/validate as a `dsm.anchor.OfflineRelease`.
    Malformed,
    /// No anchor enrollment is pinned for this counterparty.
    AnchorNotEnrolled,
    /// The verified receipt proves no offline-bearer spend under the pinned
    /// bundle: there is no anchor transition of the step for a release to be.
    NotTheStepsSpend,
    /// The release's certificate names device roots other than the ones the
    /// verified receipt proves.
    RootsNotTheReceipts,
    /// The v2 acceptance predicate rejected the release.
    Predicate(AcceptError),
}

impl OfflineRecover {
    pub fn into_dsm_error(self) -> DsmError {
        DsmError::invalid_operation(format!(
            "offline transfer rejected (recover online): {self:?}"
        ))
    }
}

/// The receiver's pinned anchor enrollment for one counterparty — the values [`VerifierContext`]
/// needs to recognize a release.
pub struct PinnedAnchor {
    /// The enrolled anchor bundle `B`.
    pub bundle: [u8; 32],
    /// The enrolled TROPIC01 anchor identity (`stpub`).
    pub anchor_id: [u8; 32],
    /// The enrolled counter `H₀`.
    pub enrolled_counter: u64,
    /// The pinned RP2350 partition public key `pk_host` (`σ^host`).
    pub partition_pk: Vec<u8>,
    /// The pinned resident chip public key `pk_chip` (`σ^chip`, Ed25519).
    pub pk_chip: Vec<u8>,
    /// `true` iff no firmware-boundary / physical-compromise / policy event invalidates it.
    pub uncompromised: bool,
}

impl PinnedAnchor {
    /// Adapt the receiver-side fused-anchor enrollment (`dsm` core owns `FusedAnchorPin`).
    pub fn from_fused(p: &dsm::crypto::anchor_enrollment::FusedAnchorPin) -> Self {
        Self {
            bundle: p.bundle,
            anchor_id: p.anchor_id,
            enrolled_counter: p.enrolled_counter,
            partition_pk: p.partition_pk.clone(),
            pk_chip: p.pk_chip.clone(),
            uncompromised: p.uncompromised,
        }
    }
}

/// Receiver-side Ed25519 verification of `σ^chip`. The resident chip signs on-die; the receiver
/// verifies against the enrolled `pk_chip` with strict Ed25519.
struct Ed25519ChipSig;
impl ChipSig for Ed25519ChipSig {
    fn verify(pk_chip: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
        let (Ok(pk), Ok(sig)) = (<[u8; 32]>::try_from(pk_chip), <[u8; 64]>::try_from(sig)) else {
            return false;
        };
        dsm::crypto::classical_verify::verify_ed25519(&pk, message, &sig).is_ok()
    }
}

/// SPHINCS+ partition (`σ^host`) verifier — reuses the host `dsm::crypto::sphincs` scheme under the
/// receiver-pinned `pk_host`.
struct SphincsPart;
impl anchor_core::tropic::PartitionSig for SphincsPart {
    fn part_keygen(_seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        // The receiver never generates a partition key; it only verifies.
        (Vec::new(), Vec::new())
    }
    fn part_sign(_sk: &[u8], _digest: &[u8; 32]) -> Vec<u8> {
        Vec::new()
    }
    fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        dsm::crypto::sphincs::verify(PARTITION_VARIANT, pk, digest, sig).unwrap_or(false)
    }
}

/// Device-SMT verifier (`DsmVerifier`). Delegates to the DSM SMT anchor-state leaf inclusion check;
/// never reimplements anchor crypto. The inclusion proofs `Π_i`/`Π_{i+1}` are carried IN the release
/// and passed to `verify_smt_leaf` by the predicate.
struct DsmStateVerifier<'a> {
    receiver_device_id: &'a [u8; 32],
    /// The pinned bundle `B` — the SMT leaf key is `anchor_state_leaf_key(B)`.
    bundle: &'a [u8; 32],
    /// The anchor-state leaves, before and after, that the step's verified
    /// receipt proves its write set moved.
    verified: &'a dsm::verification::receipt_verification::BearerLeaves,
    /// The release's anchor counter `u_i`.
    anchor_counter: u64,
}

impl DsmVerifier for DsmStateVerifier<'_> {
    fn verify_smt_leaf(&self, root: &[u8; 32], proof: &[u8], leaf: &[u8; 32]) -> bool {
        // `leaf` = anchor_state_leaf(B, h, u) (computed by the predicate). Check the SMT inclusion
        // proof binds exactly this leaf value, at key anchor_state_leaf_key(B), under `root` (= R_i
        // or R_{i+1}). An empty/absent proof (producer has not attached Π yet) fails closed.
        dsm::core::bilateral_transaction_manager::verify_anchor_state_leaf(
            root,
            self.bundle,
            leaf,
            proof,
        )
    }

    fn verify_transition(
        &self,
        _transition_digest: &[u8; 32],
        prev_frontier: &[u8; 32],
        next_frontier: &[u8; 32],
    ) -> bool {
        // The trait names the frontier pair `prev_root`/`next_root`; `accept_offline` passes
        // `cert.prev_frontier` and `cert.next_frontier`, anchor frontiers. Def. 12 step 12 asks
        // for `σ^DSM` over the transition and the whole-state consumption `R_i → R_{i+1}`. Both
        // are in the stitched receipt `decide_confirm` verified, which this verifier holds: its
        // A-side EK signature is `σ^DSM`, and its write set folds `R_i` to `R_{i+1}`, moving this
        // anchor-state leaf from `verified.anchor_before` to `verified.anchor_after`. The
        // transition is that consumption when its frontiers, at the release's counter and its
        // successor under the pinned bundle, are exactly those two leaves. The digest is bound
        // through the successor frontier, `H(h_i ‖ D)`, which checks 7-11 tie to the transition.
        self.anchor_counter
            .checked_add(1)
            .is_some_and(|next_counter| {
                self.verified.bundle == *self.bundle
                    && anchor_core::root_advance::anchor_state_leaf(
                        self.bundle,
                        prev_frontier,
                        self.anchor_counter,
                    ) == self.verified.anchor_before
                    && anchor_core::root_advance::anchor_state_leaf(
                        self.bundle,
                        next_frontier,
                        next_counter,
                    ) == self.verified.anchor_after
            })
    }

    fn delivers_to_receiver(&self, _transition_digest: &[u8; 32], recipient: &[u8; 32]) -> bool {
        recipient == self.receiver_device_id
    }

    fn verify_upgrade_cert(&self, _bundle: &[u8; 32]) -> bool {
        // Dormant in Stage 3: acceptance sets is_genesis=false, so the predicate never reaches this.
        // First-transfer admission stays TOFU (`pin_admit_decision`); the real dual-identity upgrade
        // cert is Stage 5.
        //
        // FAILS CLOSED rather than returning true. Because the hook is unreachable today the two
        // answers are behaviourally identical NOW, which is exactly why the choice matters: whoever
        // first sets `is_genesis = true` inherits whatever this returns. `true` would silently admit
        // every genesis release. `false` refuses them until the Stage 5 cert is implemented, which
        // is a visible failure that names this function instead of a silent admission.
        false
    }
}

/// Receiver-admit fold: the decision for a sender's anchor disclosure against the receiver's pin
/// state. PURE — no store, no I/O; the confirm handler applies it inside the offline branch, bound
/// to that transfer, under the surrounding gates (offline op, verified contact, disclosure present).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PinAdmitDecision {
    /// No existing pin: admit the disclosed pin (first-transfer TOFU under the verified contact).
    Admit(dsm::crypto::anchor_enrollment::AnchorEnrollment),
    /// Already pinned and the disclosure matches: keep the pin untouched.
    NoChange,
    /// The disclosure CONFLICTS with the pinned anchor (differing anchor_id / bundle / policy / H0 /
    /// pk_host / pk_chip). A changed anchor after pinning is a silent-substitution attack: keep the
    /// pinned anchor, never overwrite from a transfer.
    Reject(&'static str),
}

/// Decide admit/no-change/reject for a disclosed pin. `disclosed.uncompromised` is ignored — the
/// admitted flag is set true and thereafter only invalidated out of band.
pub(crate) fn pin_admit_decision(
    device_id: [u8; 32],
    disclosed_policy: [u8; 32],
    disclosed: &dsm::crypto::anchor_enrollment::FusedAnchorPin,
    existing: Option<&dsm::crypto::anchor_enrollment::AnchorEnrollment>,
) -> PinAdmitDecision {
    let Some(cur) = existing else {
        return PinAdmitDecision::Admit(dsm::crypto::anchor_enrollment::AnchorEnrollment {
            device_id,
            policy_hash: disclosed_policy,
            pin: dsm::crypto::anchor_enrollment::FusedAnchorPin {
                uncompromised: true,
                ..disclosed.clone()
            },
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
    PinAdmitDecision::NoChange
}

/// The anchor-state leaves a sender's offline-bearer step moves, DERIVED — never read — from its
/// release: the counter's successor is `u_i + 1`, and the frontier's successor is
/// `anchor_root_advance(h_i, D_{i+1})` with `D_{i+1}` recomputed from the release's transition
/// under this receiver's own challenge `r_R`. Both leaves are under `bundle`, the one this
/// receiver pins (or is admitting) for the sender. A release whose carried successor is not the
/// derived one is refused. The release's signatures are checked by [`accept_offline_release`]
/// before anything commits; these leaves are what the step's receipt must prove it moved.
pub fn bearer_leaves_of_release(
    offline_release: &[u8],
    bundle: &[u8; 32],
    receiver_challenge: &[u8; 32],
) -> Result<dsm::verification::receipt_verification::BearerLeaves, OfflineRecover> {
    use anchor_core::root_advance::{anchor_root_advance, anchor_state_leaf, transition_digest};
    let rel = decode_release(offline_release)?;
    let t = rel.transition.as_transition();
    let next_counter = t
        .anchor_counter
        .checked_add(1)
        .ok_or(OfflineRecover::Malformed)?;
    let next_frontier =
        anchor_root_advance(t.prev_root, &transition_digest(&t, receiver_challenge));
    if t.next_anchor_counter != next_counter || *t.next_root != next_frontier {
        return Err(OfflineRecover::Predicate(
            AcceptError::TransitionProofInvalid,
        ));
    }
    Ok(dsm::verification::receipt_verification::BearerLeaves {
        bundle: *bundle,
        anchor_before: anchor_state_leaf(bundle, t.prev_root, t.anchor_counter),
        anchor_after: anchor_state_leaf(bundle, &next_frontier, next_counter),
    })
}

/// The holder's successor frontier state, returned on acceptance so the receiver can ADOPT it
/// (persist as the new accepted frontier) once the canonical commit succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdoptedAnchorState {
    /// The release's `next_root` — the frontier `h_{i+1}` the next transfer consumes.
    pub next_root: [u8; 32],
    /// The release's `next_anchor_counter` (`u_i + 1`) adopted with it.
    pub next_anchor_counter: u64,
}

/// Apply the v2 acceptance predicate to an inbound offline confirm. Fail-closed: `Err(OfflineRecover)`
/// (release no value, recover online) on a missing/malformed release, an un-enrolled anchor, or ANY
/// failed predicate check. On `Ok(adopted)` the receiver proceeds to the canonical value-release
/// commit and, after that succeeds, persists `adopted` as the holder's accepted frontier.
///
/// `verified` is the confirm [`dsm::bilateral::offline::decide_confirm`] decided: the predicate's
/// step 12 is the consumption its receipt proves, so there is no way to run the predicate without
/// a verified receipt, and the device roots and anchor leaves are the receipt's, never values the
/// caller supplies.
///
/// `accepted_frontier`: the frontier adopted from the holder's last accepted release. `None` =
/// relationship genesis (nothing adopted yet) — the release's own `prev_root` is adopted TOFU; its
/// authenticity rests on the anchor-state inclusion proofs + the three signatures, the same trust
/// root as the first-transfer pin admit.
pub fn accept_offline_release(
    verified: &dsm::bilateral::offline::VerifiedConfirm,
    offline_release: &[u8],
    pinned: Option<&PinnedAnchor>,
    accepted_frontier: Option<&[u8; 32]>,
    receiver_device_id: &[u8; 32],
    expected_receiver_challenge: &[u8; 32],
    expected_policy_hash: &[u8; 32],
) -> Result<AdoptedAnchorState, OfflineRecover> {
    let rel = decode_release(offline_release)?;
    let pinned = pinned.ok_or(OfflineRecover::AnchorNotEnrolled)?;
    let spend = verified
        .bearer()
        .filter(|leaves| leaves.bundle == pinned.bundle)
        .ok_or(OfflineRecover::NotTheStepsSpend)?;

    // Tie the cert's device roots to the roots the verified receipt proves (its write set folds the
    // one to the other). The predicate checks Π against the CERT roots; if the cert roots were not
    // the receipt's, the sender could sign an arbitrary parallel tree — reject before running the
    // predicate.
    let receipt = verified.receipt();
    if rel.cert.sender_device_root_before != receipt.parent_root
        || rel.cert.sender_device_root_after != receipt.child_root
    {
        return Err(OfflineRecover::RootsNotTheReceipts);
    }

    let t = rel.transition.as_transition();
    // The receiver's adopted frontier for this holder, or (genesis) the release's own prev_root TOFU.
    let effective_frontier: [u8; 32] = match accepted_frontier {
        Some(r) => *r,
        None => *t.prev_root,
    };
    let adopted = AdoptedAnchorState {
        next_root: *t.next_root,
        next_anchor_counter: t.next_anchor_counter,
    };

    let ctx = VerifierContext {
        pinned_bundle: &pinned.bundle,
        pinned_anchor_id: &pinned.anchor_id,
        pinned_pk_chip: &pinned.pk_chip,
        pinned_pk_host: &pinned.partition_pk,
        accepted_frontier: &effective_frontier,
        expected_receiver_challenge,
        expected_recipient: receiver_device_id,
        expected_policy_hash,
        anchor_uncompromised: pinned.uncompromised,
        // Stage 3: genesis handling stays TOFU (pin_admit_decision); the upgrade cert is Stage 5.
        is_genesis: false,
    };
    let dsm = DsmStateVerifier {
        receiver_device_id,
        bundle: &pinned.bundle,
        verified: spend,
        anchor_counter: t.anchor_counter,
    };
    accept_offline::<_, Ed25519ChipSig, SphincsPart>(&rel, &ctx, &dsm)
        .map_err(OfflineRecover::Predicate)?;
    Ok(adopted)
}

/// The release a confirm carries, decoded and validated as a `dsm.anchor.OfflineRelease`.
fn decode_release(
    offline_release: &[u8],
) -> Result<anchor_core::root_advance::OfflineRelease, OfflineRecover> {
    if offline_release.is_empty() {
        return Err(OfflineRecover::MissingRelease);
    }
    pb::OfflineRelease::decode(offline_release)
        .map_err(|e| {
            log::warn!("offline release does not decode: {e}");
            OfflineRecover::Malformed
        })?
        .to_release()
        .map_err(|e| {
            log::warn!("offline release does not validate: {e:?}");
            OfflineRecover::Malformed
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The genesis upgrade-cert hook is unreachable today (`is_genesis` is hardcoded `false` at
    /// every construction site), so this is the only way to observe what it answers. It must be
    /// `false`.
    ///
    /// The point is precisely that the hook is dormant: whoever first sets `is_genesis = true`
    /// inherits this answer. `true` would silently admit every genesis release; `false` refuses
    /// them with a named error until the Stage 5 dual-identity cert exists.
    #[test]
    fn the_dormant_genesis_upgrade_cert_hook_fails_closed() {
        let receiver = [7u8; 32];
        let bundle = [9u8; 32];
        let leaves = dsm::verification::receipt_verification::BearerLeaves {
            bundle,
            anchor_before: [0x0Au8; 32],
            anchor_after: [0x0Bu8; 32],
        };
        let dsm = DsmStateVerifier {
            receiver_device_id: &receiver,
            bundle: &bundle,
            verified: &leaves,
            anchor_counter: 4,
        };
        assert!(
            !dsm.verify_upgrade_cert(&bundle),
            "verify_upgrade_cert returned true while dormant — the first caller to set \
             is_genesis=true would admit genesis releases with no cert check at all"
        );
    }

    /// SA-54. Def. 12 step 12 is the consumption the verified receipt proves: the transition's
    /// frontier pair, at the release's counter and its successor under the pinned bundle, must
    /// be the anchor-state leaves the receipt's write set moves. Any other frontier, counter or
    /// bundle is not that consumption.
    /// MUTATION CONTROL: answering the hook without the leaves (any constant answer, or one
    /// that ignores a frontier) turns this red.
    #[test]
    fn the_transition_is_only_the_consumption_the_verified_receipt_proves() {
        use anchor_core::root_advance::anchor_state_leaf;
        let receiver = [7u8; 32];
        let bundle = [9u8; 32];
        let (prev, next, counter) = ([0x21u8; 32], [0x22u8; 32], 41u64);
        let leaves = dsm::verification::receipt_verification::BearerLeaves {
            bundle,
            anchor_before: anchor_state_leaf(&bundle, &prev, counter),
            anchor_after: anchor_state_leaf(&bundle, &next, counter + 1),
        };
        let digest = [0x23u8; 32];
        let check = |bundle: &[u8; 32], counter: u64, prev: &[u8; 32], next: &[u8; 32]| {
            DsmStateVerifier {
                receiver_device_id: &receiver,
                bundle,
                verified: &leaves,
                anchor_counter: counter,
            }
            .verify_transition(&digest, prev, next)
        };

        assert!(
            check(&bundle, counter, &prev, &next),
            "the step's own transition"
        );
        assert!(
            !check(&bundle, counter, &next, &prev),
            "the frontiers reversed"
        );
        assert!(
            !check(&bundle, counter, &prev, &prev),
            "another successor frontier"
        );
        assert!(
            !check(&bundle, counter, &next, &next),
            "another prior frontier"
        );
        assert!(
            !check(&bundle, counter + 1, &prev, &next),
            "another counter"
        );
        assert!(
            !check(&[0x0Cu8; 32], counter, &prev, &next),
            "another bundle"
        );
        assert!(
            !check(&bundle, u64::MAX, &prev, &next),
            "a counter with no successor"
        );
    }

    /// A release that is absent, or does not decode and validate, is refused before anything
    /// else is read.
    #[test]
    fn a_missing_or_malformed_release_routes_online() {
        assert!(matches!(
            decode_release(&[]),
            Err(OfflineRecover::MissingRelease)
        ));
        // Non-empty bytes with no transition/cert: decodes as a proto but fails `to_release`.
        let bytes = pb::OfflineRelease {
            anchor_smt_proof_before: vec![0x01],
            ..Default::default()
        }
        .encode_to_vec();
        assert!(matches!(
            decode_release(&bytes),
            Err(OfflineRecover::Malformed)
        ));
    }

    // --- receiver-admit fold: pin_admit_decision matrix ---

    fn fused_pin() -> dsm::crypto::anchor_enrollment::FusedAnchorPin {
        dsm::crypto::anchor_enrollment::FusedAnchorPin {
            bundle: [0xB1; 32],
            anchor_id: [0xA1; 32],
            enrolled_counter: 1_000_000,
            partition_pk: vec![0x07; 64],
            pk_chip: vec![0x0C; 32],
            uncompromised: true,
        }
    }

    fn pinned() -> dsm::crypto::anchor_enrollment::AnchorEnrollment {
        dsm::crypto::anchor_enrollment::AnchorEnrollment {
            device_id: [0x11; 32],
            policy_hash: [0x9A; 32],
            pin: fused_pin(),
        }
    }

    #[test]
    fn pin_admit_decision_first_transfer_admits_under_disclosed_policy() {
        let d = fused_pin();
        match pin_admit_decision([0x11; 32], [0x9A; 32], &d, None) {
            PinAdmitDecision::Admit(e) => {
                assert_eq!(e.device_id, [0x11; 32]);
                assert_eq!(e.policy_hash, [0x9A; 32]);
                assert_eq!(e.pin.anchor_id, [0xA1; 32]);
                assert_eq!(e.pin.pk_chip, vec![0x0C; 32]);
                assert!(e.pin.uncompromised, "admission sets uncompromised=true");
            }
            other => panic!("expected Admit, got {other:?}"),
        }
    }

    #[test]
    fn pin_admit_decision_no_change_when_disclosure_matches() {
        let cur = pinned();
        assert_eq!(
            pin_admit_decision([0x11; 32], [0x9A; 32], &fused_pin(), Some(&cur)),
            PinAdmitDecision::NoChange
        );
    }

    #[test]
    fn pin_admit_decision_rejects_every_conflicting_disclosure() {
        let cur = pinned();
        let base = fused_pin();

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
                    pin_admit_decision([0x11; 32], [0x9A; 32], d, Some(&cur)),
                    PinAdmitDecision::Reject(_)
                ),
                "conflicting disclosure must be rejected: {d:?}"
            );
        }
        // Differing policy rejects too.
        assert!(matches!(
            pin_admit_decision([0x11; 32], [0x9B; 32], &base, Some(&cur)),
            PinAdmitDecision::Reject(_)
        ));
    }
}
