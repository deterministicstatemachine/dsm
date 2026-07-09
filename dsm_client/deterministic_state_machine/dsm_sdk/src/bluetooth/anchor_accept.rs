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
    /// The v2 acceptance predicate rejected the release.
    Predicate(AcceptError),
}

impl OfflineRecover {
    pub fn into_dsm_error(self) -> DsmError {
        DsmError::invalid_operation(format!("offline transfer rejected (recover online): {self:?}"))
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
}

impl DsmVerifier for DsmStateVerifier<'_> {
    fn verify_smt_leaf(&self, root: &[u8; 32], proof: &[u8], leaf: &[u8; 32]) -> bool {
        // `leaf` = anchor_state_leaf(B, h, u) (computed by the predicate). Check the SMT inclusion
        // proof binds exactly this leaf value, at key anchor_state_leaf_key(B), under `root` (= R_i
        // or R_{i+1}). An empty/absent proof (producer has not attached Π yet) fails closed.
        dsm::core::bilateral_transaction_manager::verify_anchor_state_leaf(root, self.bundle, leaf, proof)
    }

    fn verify_transition(
        &self,
        _transition_digest: &[u8; 32],
        _prev_root: &[u8; 32],
        _next_root: &[u8; 32],
    ) -> bool {
        // The DSM relationship transition `h_i → h_{i+1}` (and its `σ^DSM`) is validated by the
        // bilateral handler's existing checks that GATE this predicate: `rel_proof_parent`
        // (h_n ∈ R_i) + `rel_proof_child` (h_{n+1} ∈ R_{i+1}) + the §C1 h_{n+1} recompute, and the
        // accepted-frontier pin. The handler fails closed BEFORE calling accept if any fail.
        true
    }

    fn delivers_to_receiver(&self, _transition_digest: &[u8; 32], recipient: &[u8; 32]) -> bool {
        recipient == self.receiver_device_id
    }

    fn verify_upgrade_cert(&self, _bundle: &[u8; 32]) -> bool {
        // Dormant in Stage 3: acceptance sets is_genesis=false and never calls this. First-transfer
        // admission stays TOFU (`pin_admit_decision`). The real dual-identity upgrade cert is Stage 5.
        true
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
/// `accepted_frontier`: the frontier adopted from the holder's last accepted release. `None` =
/// relationship genesis (nothing adopted yet) — the release's own `prev_root` is adopted TOFU; its
/// authenticity rests on the anchor-state inclusion proofs + the three signatures, the same trust
/// root as the first-transfer pin admit.
pub fn accept_offline_release(
    offline_release: &[u8],
    pinned: Option<&PinnedAnchor>,
    accepted_frontier: Option<&[u8; 32]>,
    receiver_device_id: &[u8; 32],
    expected_receiver_challenge: &[u8; 32],
    expected_policy_hash: &[u8; 32],
    expected_sender_device_root_before: &[u8; 32],
    expected_sender_device_root_after: &[u8; 32],
) -> Result<AdoptedAnchorState, OfflineRecover> {
    if offline_release.is_empty() {
        return Err(OfflineRecover::MissingRelease);
    }
    let rel = pb::OfflineRelease::decode(offline_release)
        .map_err(|_| OfflineRecover::Malformed)?
        .to_release()
        .map_err(|_| OfflineRecover::Malformed)?;
    let pinned = pinned.ok_or(OfflineRecover::AnchorNotEnrolled)?;

    // Tie the cert's device roots to the roots the handler INDEPENDENTLY verified from the confirm
    // (rel_proof_parent/child + §C1 recompute). The predicate checks Π against the CERT roots; if
    // the cert roots were not the actual verified device roots, the sender could sign an arbitrary
    // parallel tree — reject before running the predicate.
    if rel.cert.sender_device_root_before != *expected_sender_device_root_before
        || rel.cert.sender_device_root_after != *expected_sender_device_root_after
    {
        return Err(OfflineRecover::Predicate(AcceptError::TransitionProofInvalid));
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
    };
    accept_offline::<_, Ed25519ChipSig, SphincsPart>(&rel, &ctx, &dsm)
        .map_err(OfflineRecover::Predicate)?;
    Ok(adopted)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const ZERO: [u8; 32] = [0u8; 32];

    fn z() -> Vec<u8> {
        vec![0u8; 32]
    }

    fn pin() -> PinnedAnchor {
        PinnedAnchor {
            bundle: ZERO,
            anchor_id: ZERO,
            enrolled_counter: 100,
            partition_pk: vec![0u8; 64],
            pk_chip: vec![0u8; 32],
            uncompromised: true,
        }
    }

    /// A `dsm.anchor.OfflineRelease` whose fixed-width fields all decode (passes `to_release`) but
    /// whose cert cannot satisfy the predicate — so it reaches and is rejected by `accept_offline`.
    fn decodable_release_bytes() -> Vec<u8> {
        let transition = pb::TransitionPackage {
            relationship_id: z(),
            object_id: z(),
            sender_device_id: z(),
            recipient_device_id: z(),
            prev_root: z(),
            next_root: z(),
            anchor_counter: 0,
            next_anchor_counter: 1,
            action_type: 0,
            action_fields: vec![],
            payload_hash: z(),
            old_leaf_proof: vec![],
            new_leaf_proof: vec![],
            authority_policy_hash: z(),
        };
        let cert = pb::RootAdvanceCertificate {
            anchor_bundle: z(),
            sender_device_root_before: z(),
            sender_device_root_after: z(),
            prev_frontier: z(),
            next_frontier: z(),
            anchor_counter: 0,
            next_anchor_counter: 1,
            transition_digest: z(),
            root_advance_message: z(),
            anchor_id: z(),
            sigma_chip: vec![],
            sigma_host: vec![],
            receiver_challenge: z(),
            recipient: z(),
        };
        pb::OfflineRelease {
            transition: Some(transition),
            anchor_smt_proof_before: vec![],
            anchor_smt_proof_after: vec![],
            cert: Some(cert),
            branch_proof: vec![],
        }
        .encode_to_vec()
    }

    #[test]
    fn missing_release_routes_online() {
        let r = accept_offline_release(&[], Some(&pin()), Some(&ZERO), &ZERO, &ZERO, &ZERO, &ZERO, &ZERO);
        assert!(matches!(r, Err(OfflineRecover::MissingRelease)));
    }

    #[test]
    fn malformed_release_routes_online() {
        // Non-empty bytes with no transition/cert: decodes as a proto but fails `to_release`.
        let bytes = pb::OfflineRelease {
            anchor_smt_proof_before: vec![0x01],
            ..Default::default()
        }
        .encode_to_vec();
        let r = accept_offline_release(&bytes, Some(&pin()), Some(&ZERO), &ZERO, &ZERO, &ZERO, &ZERO, &ZERO);
        assert!(matches!(r, Err(OfflineRecover::Malformed)));
    }

    #[test]
    fn unenrolled_anchor_routes_online() {
        let bytes = decodable_release_bytes();
        let r = accept_offline_release(&bytes, None, Some(&ZERO), &ZERO, &ZERO, &ZERO, &ZERO, &ZERO);
        assert!(matches!(r, Err(OfflineRecover::AnchorNotEnrolled)));
    }

    #[test]
    fn predicate_rejects_and_routes_online() {
        // A decodable release WITH a pin reaches accept_offline and is rejected (proves the canonical
        // predicate is wired + fail-closed — an all-zero cert can never satisfy it).
        let bytes = decodable_release_bytes();
        let r = accept_offline_release(&bytes, Some(&pin()), Some(&ZERO), &ZERO, &ZERO, &ZERO, &ZERO, &ZERO);
        assert!(matches!(r, Err(OfflineRecover::Predicate(_))));
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
