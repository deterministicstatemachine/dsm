// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical offline-bearer acceptance for the bilateral RECEIVER path: the Boot
//! Fenced Fused Anchor predicate (`anchor_core::accept::accept_offline`, 22 checks).
//!
//! This is the canonical replacement for the legacy Safe 7 IslandAttestation receiver
//! acceptance. The DSM app supplies two adapters and NEVER reimplements anchor crypto:
//!   - [`DsmStateVerifier`] (`DsmVerifier`): DSM SMT/root commitments, the DSM transition
//!     proof, the boot chain, and the partition certificate — the partition cert reuses the
//!     existing `dsm::crypto::sphincs` verifier under the receiver-pinned partition key.
//!   - [`DsmCounterVerifier`] (`CounterVerifier`): the authenticated TROPIC01 counter, read
//!     ONLY from `ev.verifier_transcript`, NEVER a host-supplied `*_claim` field.
//!
//! Fail-closed posture (Phase 4). Three producer-side inputs do not exist yet: the sender
//! does not ride an `OfflineRelease`, there is no authenticated counter-read transcript, and
//! the DSM SMT leaf does not yet commit the fused anchor state `(B, Aᵢ, J_b, uᵢ)` (spec §6).
//! Until they ship (Phase 5) every offline-bearer transfer routes to ONLINE RECOVERY — an
//! absent/malformed release, an un-enrolled anchor, an empty/inauthentic counter transcript,
//! or ANY failed predicate check rejects before any value is released. There is no
//! IslandAttestation fallback and no degraded-acceptance path.

use anchor_core::accept::{accept_offline, AcceptError, CounterVerifier, DsmVerifier, VerifierContext};
use anchor_core::boot::BootTicket;
use anchor_core::proto::pb;
use anchor_core::root_advance::{CounterEvidence, Transition};
use anchor_core::sig::WotsBlake3;
use prost::Message;

use dsm::types::error::DsmError;

/// The partition-certificate scheme the RP2350 secure partition signs with: BLAKE3-SPHINCS+
/// SPX128f, byte-compatible with `dsm::crypto::sphincs` (the `DSM/sphincs-kdf` scheme).
const PARTITION_VARIANT: dsm::crypto::sphincs::SphincsVariant =
    dsm::crypto::sphincs::SphincsVariant::SPX128f;

/// Why an offline-bearer transfer was not accepted. Every variant means the same thing to the
/// caller: release no value, recover online. The legacy Safe 7 shape maps to [`MissingRelease`].
#[derive(Debug)]
pub enum OfflineRecover {
    /// No canonical release on the confirm — an absent `offline_release`, or a legacy
    /// IslandAttestation-only confirm (the legacy offline-bearer shape is no longer accepted).
    MissingRelease,
    /// The release bytes did not decode/validate as a `dsm.anchor.OfflineRelease`.
    Malformed,
    /// No anchor-core enrollment is pinned for this counterparty (Phase 5 enrollment).
    AnchorNotEnrolled,
    /// The Boot Fenced Fused Anchor predicate rejected the release.
    Predicate(AcceptError),
}

impl OfflineRecover {
    /// Surface as the handler's error — returned before any value release, so the offline
    /// transfer fails closed and the caller recovers online.
    pub fn into_dsm_error(self) -> DsmError {
        DsmError::invalid_operation(format!(
            "offline-bearer rejected (recover online): {self:?}"
        ))
    }
}

/// The receiver's pinned anchor-core enrollment for one counterparty — the values
/// [`VerifierContext`] needs to recognize a release. Pinned at enrollment (Phase 5); no
/// enrollment exists yet, so the live seam passes `None` and every transfer recovers online.
pub struct PinnedAnchor {
    /// The enrolled anchor bundle `B`.
    pub bundle: [u8; 32],
    /// The enrolled TROPIC01 anchor identity.
    pub anchor_id: [u8; 32],
    /// The enrolled counter `H₀`.
    pub enrolled_counter: u64,
    /// The pinned RP2350 partition public key (verifies the boot + final certs).
    pub partition_pk: Vec<u8>,
    /// `true` iff no firmware-boundary / physical-compromise / policy event invalidates it.
    pub uncompromised: bool,
}

/// DSM-state + partition + boot-chain verifier (`DsmVerifier`). Delegates to the existing DSM
/// SMT and SPHINCS+ verifiers; never reimplements anchor crypto. The anchor-state SMT
/// commitment (spec §6) and the DSM transition proof are Phase 5 — fail-closed here.
struct DsmStateVerifier<'a> {
    receiver_device_id: &'a [u8; 32],
    partition_pk: &'a [u8],
}

impl DsmStateVerifier<'_> {
    /// Reuse the host BLAKE3-SPHINCS+ verifier (the same `DSM/sphincs-kdf` scheme the anchor
    /// signs with). Never reimplement SPHINCS+ here.
    fn part_verify(&self, m: &[u8; 32], sig: &[u8]) -> bool {
        dsm::crypto::sphincs::verify(PARTITION_VARIANT, self.partition_pk, m, sig).unwrap_or(false)
    }
}

impl DsmVerifier for DsmStateVerifier<'_> {
    fn prev_root_commits_anchor_state(
        &self,
        _prev_root: &[u8; 32],
        _bundle: &[u8; 32],
        _anchor_head: &[u8; 32],
        _boot_head: &[u8; 32],
        _anchor_counter: u64,
    ) -> bool {
        // Phase 5: verify SMT inclusion of the leaf committing (B, Aᵢ, J_b, uᵢ) in prev_root
        // (spec §6 — the anchor index is committed into the DSM parent state) via
        // dsm::verification::proof_primitives::verify_smt_inclusion_proof_bytes. The DSM SMT
        // leaf does not encode the fused anchor state yet, so fail closed -> online recovery.
        false
    }

    fn verify_boot_chain(
        &self,
        bundle: &[u8; 32],
        anchor_head: &[u8; 32],
        committed_boot_head: &[u8; 32],
        current_boot_head: &[u8; 32],
        boot_chain: &[BootTicket],
    ) -> bool {
        // Each ticket must chain from the committed boot head and carry a partition boot cert
        // that verifies under the pinned partition key (mirrors the firmware receiver).
        if self.partition_pk.is_empty() {
            return false;
        }
        let mut prev = *committed_boot_head;
        for tk in boot_chain {
            if &tk.anchor_bundle != bundle
                || &tk.anchor_head != anchor_head
                || tk.prev_boot_head != prev
            {
                return false;
            }
            if !self.part_verify(&tk.cert_message(), &tk.partition_boot_signature) {
                return false;
            }
            prev = tk.next_boot_head;
        }
        &prev == current_boot_head
    }

    fn verify_partition_certificate(&self, m_p: &[u8; 32], sigma_partition: &[u8]) -> bool {
        self.part_verify(m_p, sigma_partition)
    }

    fn verify_transition(&self, _t: &Transition) -> bool {
        // Phase 5: bridge the anchor-core transition proof (old/new leaf proofs) to the DSM SMT
        // verifier (verify_smt_inclusion_proof_bytes + verify_tripwire_smt_replace). The
        // producer does not emit DSM-shaped proofs yet, so fail closed -> online recovery.
        false
    }

    fn delivers_to_receiver(&self, t: &Transition) -> bool {
        t.recipient_device_id == self.receiver_device_id
    }

    fn next_root_commits_anchor_state(
        &self,
        _next_root: &[u8; 32],
        _bundle: &[u8; 32],
        _next_anchor_head: &[u8; 32],
        _boot_head: &[u8; 32],
        _next_anchor_counter: u64,
    ) -> bool {
        // Phase 5 — see prev_root_commits_anchor_state.
        false
    }
}

/// Authenticated-counter verifier (`CounterVerifier`). Returns ONLY the transcript-attested
/// counter; NEVER the host-supplied `live_counter_claim` / `derived_anchor_counter_claim`.
/// Phase 4: no authenticated transcript format exists (the anchor emits an empty transcript),
/// so this always fails closed.
struct DsmCounterVerifier;

impl CounterVerifier for DsmCounterVerifier {
    fn read_authentic_counter(&self, _anchor_id: &[u8; 32], ev: &CounterEvidence) -> Option<u64> {
        if ev.verifier_transcript.is_empty() {
            return None; // no authenticated counter evidence -> reject -> online recovery
        }
        // Phase 5: open a receiver-operated authenticated TROPIC01 L3 verifier-pairing-slot
        // session (or verify a signed counter transcript under the receiver-pinned counter key),
        // recompute u = H0 - H, and return Some(u). Until then, reject. NEVER read
        // ev.live_counter_claim / ev.derived_anchor_counter_claim (host-supplied, untrusted).
        None
    }
}

/// Apply the canonical Boot Fenced Fused Anchor acceptance predicate to an inbound
/// offline-bearer confirm. Fail-closed: returns `Err(OfflineRecover)` (release no value,
/// recover online) on a missing/malformed release, an un-enrolled anchor, or ANY failed
/// predicate check — including the unauthenticated counter. On `Ok(())` the receiver may
/// proceed to the canonical value-release commit.
pub fn accept_offline_release(
    offline_release: &[u8],
    pinned: Option<&PinnedAnchor>,
    accepted_prev_root: &[u8; 32],
    receiver_device_id: &[u8; 32],
    expected_receiver_challenge: &[u8; 32],
    expected_policy_hash: &[u8; 32],
) -> Result<(), OfflineRecover> {
    if offline_release.is_empty() {
        // Absent canonical release (or a legacy IslandAttestation-only confirm).
        return Err(OfflineRecover::MissingRelease);
    }
    let rel = pb::OfflineRelease::decode(offline_release)
        .map_err(|_| OfflineRecover::Malformed)?
        .to_release()
        .map_err(|_| OfflineRecover::Malformed)?;
    let pinned = pinned.ok_or(OfflineRecover::AnchorNotEnrolled)?;

    let ctx = VerifierContext {
        accepted_prev_root,
        pinned_bundle: &pinned.bundle,
        pinned_anchor_id: &pinned.anchor_id,
        expected_receiver_challenge,
        expected_policy_hash,
        enrolled_counter: pinned.enrolled_counter,
        anchor_uncompromised: pinned.uncompromised,
    };
    let dsm = DsmStateVerifier {
        receiver_device_id,
        partition_pk: &pinned.partition_pk,
    };
    accept_offline::<WotsBlake3, _, _>(&rel, &ctx, &dsm, &DsmCounterVerifier)
        .map_err(OfflineRecover::Predicate)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const ZERO: [u8; 32] = [0u8; 32];

    fn pin() -> PinnedAnchor {
        PinnedAnchor {
            bundle: ZERO,
            anchor_id: ZERO,
            enrolled_counter: 100,
            partition_pk: vec![0u8; 64],
            uncompromised: true,
        }
    }

    fn z() -> Vec<u8> {
        vec![0u8; 32]
    }

    /// A `dsm.anchor.OfflineRelease` whose fixed-width fields all decode (passes `to_release`),
    /// but whose cert/counter cannot satisfy the predicate — so it reaches and is rejected by
    /// `accept_offline`.
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
            prev_anchor_head: z(),
            next_anchor_head: z(),
            prev_boot_head: z(),
            current_boot_head: z(),
            prev_root: z(),
            next_root: z(),
            anchor_counter: 0,
            next_anchor_counter: 1,
            transition_digest: z(),
            root_advance_message: z(),
            partition_commitment: z(),
            tropic_transfer_input: z(),
            pk_hash: z(),
            pk_hw: vec![],
            sigma_tropic: vec![],
            sigma_partition: vec![],
            anchor_id: z(),
            transfer_slot: 6,
            receiver_challenge: z(),
        };
        let counter = pb::CounterEvidence {
            anchor_id: z(),
            enrolled_counter: 100,
            live_counter_claim: 99,
            derived_anchor_counter_claim: 1,
            verifier_transcript: vec![],
        };
        pb::OfflineRelease {
            transition: Some(transition),
            boot_chain: vec![],
            cert: Some(cert),
            counter: Some(counter),
        }
        .encode_to_vec()
    }

    #[test]
    fn missing_release_routes_online() {
        let r = accept_offline_release(&[], Some(&pin()), &ZERO, &ZERO, &ZERO, &ZERO);
        assert!(matches!(r, Err(OfflineRecover::MissingRelease)));
    }

    #[test]
    fn malformed_release_routes_online() {
        // Non-empty but not a complete OfflineRelease (transition absent): decodes, to_release fails.
        let bytes = pb::OfflineRelease {
            counter: Some(pb::CounterEvidence::default()),
            ..Default::default()
        }
        .encode_to_vec();
        assert!(!bytes.is_empty());
        let r = accept_offline_release(&bytes, Some(&pin()), &ZERO, &ZERO, &ZERO, &ZERO);
        assert!(matches!(r, Err(OfflineRecover::Malformed)));
    }

    #[test]
    fn unenrolled_anchor_routes_online() {
        // A decodable release with NO pinned anchor (the live Phase-4 seam) recovers online.
        let bytes = decodable_release_bytes();
        let r = accept_offline_release(&bytes, None, &ZERO, &ZERO, &ZERO, &ZERO);
        assert!(matches!(r, Err(OfflineRecover::AnchorNotEnrolled)));
    }

    #[test]
    fn predicate_rejects_and_routes_online() {
        // A decodable release WITH a pin reaches accept_offline and is rejected by the predicate
        // (proves the canonical predicate is wired and fail-closed — it can never accept here).
        let bytes = decodable_release_bytes();
        let r = accept_offline_release(&bytes, Some(&pin()), &ZERO, &ZERO, &ZERO, &ZERO);
        assert!(matches!(r, Err(OfflineRecover::Predicate(_))));
    }

    #[test]
    fn counter_verifier_never_trusts_host_claim() {
        let v = DsmCounterVerifier;
        // Empty transcript -> reject.
        let empty = CounterEvidence {
            anchor_id: ZERO,
            enrolled_counter: 100,
            live_counter_claim: 99,
            derived_anchor_counter_claim: 1,
            verifier_transcript: vec![],
        };
        assert_eq!(v.read_authentic_counter(&ZERO, &empty), None);
        // Even with a populated (host-supplied) claim and a non-empty transcript, the Phase-4
        // verifier returns None — it NEVER echoes live_counter_claim / derived_anchor_counter_claim.
        let claimed = CounterEvidence {
            verifier_transcript: vec![1, 2, 3],
            ..empty
        };
        assert_eq!(v.read_authentic_counter(&ZERO, &claimed), None);
    }

    #[test]
    fn state_verifier_anchor_state_and_transition_fail_closed() {
        let rid = [7u8; 32];
        let pk = vec![0u8; 64];
        let v = DsmStateVerifier {
            receiver_device_id: &rid,
            partition_pk: &pk,
        };
        assert!(!v.prev_root_commits_anchor_state(&ZERO, &ZERO, &ZERO, &ZERO, 0));
        assert!(!v.next_root_commits_anchor_state(&ZERO, &ZERO, &ZERO, &ZERO, 1));
        assert!(!v.verify_transition(
            &pb::TransitionPackage {
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
            }
            .to_owned_transition()
            .unwrap()
            .as_transition()
        ));
    }
}
