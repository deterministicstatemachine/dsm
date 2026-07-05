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
//! Fail-closed posture. The sender now rides a real `OfflineRelease` + anchor-state proofs and
//! the receiver pins the disclosed fused anchor on the first bearer transfer, but ACCEPTANCE is
//! still gated on the authenticated Path-B counter read: the pin must be COMPLETE (verifier
//! slot + chip static key, hardware-provisioned) and a live `AnchorCounterReader` must attest
//! `H == H₀ − (uᵢ+1)` from the pinned chip. Until the device layer installs that reader, every
//! offline-bearer transfer routes to ONLINE RECOVERY — an absent/malformed release, an
//! un-enrolled anchor, an incomplete pin, or ANY failed predicate check rejects before any
//! value is released. There is no IslandAttestation fallback and no degraded-acceptance path.

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

impl PinnedAnchor {
    /// Adapt the receiver-side fused-anchor enrollment (`dsm` core owns `FusedAnchorPin`;
    /// it cannot depend on this SDK type, so the mapping lives here). A counterparty with
    /// no fused pin (legacy Safe-7 enrollment) has no `PinnedAnchor` → offline-bearer stays
    /// fail-closed and routes online.
    pub fn from_fused(p: &dsm::crypto::anchor_enrollment::FusedAnchorPin) -> Self {
        Self {
            bundle: p.bundle,
            anchor_id: p.anchor_id,
            enrolled_counter: p.enrolled_counter,
            partition_pk: p.partition_pk.clone(),
            uncompromised: p.uncompromised,
        }
    }
}

/// The DSM-SMT anchor-state binding the receiver reads off the confirm (siblings of the
/// relationship proofs `rel_proof_parent/child` + `sender_smt_root`/`_before`): the sender's device
/// roots and the two fused-anchor-state leaf inclusion proofs. `prev_proof` binds the OLD commit
/// `(B,Aᵢ,J_b,uᵢ)` under `sender_smt_root_before`; `next_proof` binds the SUCCESSOR
/// `(B,A_{i+1},J_{b'},uᵢ+1)` under `sender_smt_root`.
pub struct AnchorStateBinding<'a> {
    pub sender_smt_root: &'a [u8; 32],
    pub sender_smt_root_before: &'a [u8; 32],
    pub prev_proof: &'a [u8],
    pub next_proof: &'a [u8],
}

/// DSM-state + partition + boot-chain verifier (`DsmVerifier`). Delegates to the existing DSM
/// SMT (`verify_anchor_state_commitment`) and SPHINCS+ verifiers; never reimplements anchor crypto.
struct DsmStateVerifier<'a> {
    receiver_device_id: &'a [u8; 32],
    partition_pk: &'a [u8],
    binding: &'a AnchorStateBinding<'a>,
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
        bundle: &[u8; 32],
        anchor_head: &[u8; 32],
        boot_head: &[u8; 32],
        anchor_counter: u64,
    ) -> bool {
        // The fused anchor state `(B, Aᵢ, J_b, uᵢ)` is committed by the per-device anchor-state leaf
        // in the sender's PRE-advance device root (`sender_smt_root_before`), NOT the relationship
        // tip `prev_root` (which is symmetric). The receiver already binds `sender_smt_root_before`
        // to the accepted `h_n` via the handler's `rel_proof_parent` check that gates this predicate.
        dsm::core::bilateral_transaction_manager::verify_anchor_state_commitment(
            self.binding.sender_smt_root_before,
            bundle,
            anchor_head,
            boot_head,
            anchor_counter,
            self.binding.prev_proof,
        )
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
        // The DSM relationship transition `h_i → h_{i+1}` is validated by the bilateral handler's
        // existing checks that GATE this predicate: `rel_proof_parent` (h_n ∈ sender_smt_root_before)
        // + `rel_proof_child` (h_{n+1} ∈ sender_smt_root) + the §C1 h_{n+1} recompute, and clause 2
        // (`PrevRootNotAccepted`) pins `t.prev_root` to the receiver's accepted tip. Those bind the
        // device roots the anchor-state proofs use to the accepted transition, so this returns true
        // once reached (the handler fails closed BEFORE calling accept if any of them fail).
        true
    }

    fn delivers_to_receiver(&self, t: &Transition) -> bool {
        t.recipient_device_id == self.receiver_device_id
    }

    fn next_root_commits_anchor_state(
        &self,
        _next_root: &[u8; 32],
        bundle: &[u8; 32],
        next_anchor_head: &[u8; 32],
        boot_head: &[u8; 32],
        next_anchor_counter: u64,
    ) -> bool {
        // The successor fused state `(B, A_{i+1}, J_{b'}, uᵢ+1)` is committed by the same per-device
        // anchor-state leaf in the sender's POST-advance device root (`sender_smt_root`), bound to
        // the accepted `h_{n+1}` via the handler's `rel_proof_child` check. See
        // `prev_root_commits_anchor_state`.
        dsm::core::bilateral_transaction_manager::verify_anchor_state_commitment(
            self.binding.sender_smt_root,
            bundle,
            next_anchor_head,
            boot_head,
            next_anchor_counter,
            self.binding.next_proof,
        )
    }
}

/// Path-B authenticated-counter verifier (`CounterVerifier`). Holds the counter `H` the receiver
/// ALREADY read from the holder's TROPIC01 over its OWN authenticated libtropic-rs session (via the
/// raw-SPI relay; see `dsm-anchor-verifier`), out of band from this sync predicate — because the
/// read is many async BLE round-trips and the predicate is sync. `attested = Some((anchor_id, H))`
/// only when that authenticated read succeeded against the pinned chip; `None` = no verifier slot,
/// no live relay, or the read failed -> FAIL-CLOSED (online recovery). NEVER reads the host-supplied
/// `ev.live_counter_claim` / `ev.derived_anchor_counter_claim`.
struct DsmCounterVerifier {
    /// The authenticated live counter `H` pre-read via the relay session, tagged with the
    /// `anchor_id` it was read from (must match the release's pinned anchor). `None` -> fail-closed.
    attested: Option<([u8; 32], u64)>,
}

impl DsmCounterVerifier {
    /// The production default until the async relay read is wired: no authenticated counter -> the
    /// predicate fails closed on the counter clause and the transfer recovers online.
    fn fail_closed() -> Self {
        Self { attested: None }
    }
}

impl CounterVerifier for DsmCounterVerifier {
    fn read_authentic_counter(&self, anchor_id: &[u8; 32], _ev: &CounterEvidence) -> Option<u64> {
        // Return the pre-read authentic counter ONLY if it was read from the very chip this
        // release is pinned to; a counter read from a different anchor is not evidence for this one.
        let (read_from, h) = self.attested.as_ref()?;
        if read_from != anchor_id {
            return None;
        }
        Some(*h)
    }
}

/// Receiver-admit fold: the decision for a sender's fused-anchor disclosure against the
/// receiver's existing pin state. PURE — no store, no I/O; the confirm handler applies it inside
/// the bearer branch (bound to that transfer), and the caller owns the surrounding gates
/// (offline-bearer op, verified contact, disclosure present on THIS confirm).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PinAdmitDecision {
    /// No existing pin: admit the disclosed pin (first-transfer TOFU under the verified contact).
    Admit(dsm::crypto::anchor_enrollment::AnchorEnrollment),
    /// Same anchor identity, and the disclosure completes an incomplete pin (supplies the
    /// verifier slot / chip static key the pre-HW admission lacked): upgrade in place.
    Upgrade(dsm::crypto::anchor_enrollment::AnchorEnrollment),
    /// Already pinned and the disclosure adds nothing new: keep the pin untouched.
    NoChange,
    /// The disclosure CONFLICTS with the pinned anchor (differing anchor_id / bundle / policy /
    /// H0 / partition key / chip static key / slot). A changed anchor after pinning is a
    /// silent-substitution attack: keep the pinned anchor, never overwrite from a transfer.
    Reject(&'static str),
}

/// Decide admit/upgrade/reject for a disclosed pin. `disclosed.uncompromised` is ignored on
/// upgrade — the EXISTING flag is preserved so a disclosure can never resurrect a compromised
/// anchor.
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
        return PinAdmitDecision::Reject("disclosed partition key differs from the pinned one");
    }
    match (cur.pin.chip_static_pubkey, disclosed.chip_static_pubkey) {
        (Some(pinned), Some(new)) if pinned != new => {
            return PinAdmitDecision::Reject(
                "disclosed chip static key differs from the pinned one",
            );
        }
        _ => {}
    }
    match (cur.pin.verifier_slot, disclosed.verifier_slot) {
        (Some(pinned), Some(new)) if pinned != new => {
            return PinAdmitDecision::Reject("disclosed verifier slot differs from the pinned one");
        }
        _ => {}
    }
    let adds_slot = cur.pin.verifier_slot.is_none() && disclosed.verifier_slot.is_some();
    let adds_stpub = cur.pin.chip_static_pubkey.is_none() && disclosed.chip_static_pubkey.is_some();
    if adds_slot || adds_stpub {
        return PinAdmitDecision::Upgrade(dsm::crypto::anchor_enrollment::AnchorEnrollment {
            device_id,
            policy_hash: cur.policy_hash,
            pin: dsm::crypto::anchor_enrollment::FusedAnchorPin {
                verifier_slot: cur.pin.verifier_slot.or(disclosed.verifier_slot),
                chip_static_pubkey: cur.pin.chip_static_pubkey.or(disclosed.chip_static_pubkey),
                // Preserve the existing flag: a disclosure never resurrects a compromised anchor.
                uncompromised: cur.pin.uncompromised,
                ..cur.pin.clone()
            },
        });
    }
    PinAdmitDecision::NoChange
}

/// Admission never implies acceptance: a pinned anchor may only be COUNTER-READ when the pin is
/// COMPLETE — verifier slot provisioned, chip static key pinned (anti-substitution), and the
/// anchor uncompromised. The confirm handler consults this BEFORE invoking any installed
/// [`AnchorCounterReader`](crate::bluetooth::tropic_relay::AnchorCounterReader), so an incomplete
/// pre-HW pin can never yield `attested = Some` even against a buggy or malicious reader
/// (defense-in-depth: the hardware reader independently refuses the same conditions).
pub(crate) fn pin_ready_for_counter_read(
    pin: &dsm::crypto::anchor_enrollment::FusedAnchorPin,
) -> bool {
    pin.verifier_slot.is_some() && pin.chip_static_pubkey.is_some() && pin.uncompromised
}

/// Confirm-flow D2 seam: resolve the authenticated relay counter for this transfer. Gates the pin
/// on readiness (verifier slot + pinned chip key + uncompromised), and — only if an
/// [`AnchorCounterReader`](crate::bluetooth::tropic_relay::AnchorCounterReader) is installed —
/// reads the sender's live counter `H` over the relay. Returns `Some((anchor_id, H))` ONLY when the
/// pin is complete AND the read succeeds; every other case (no reader, incomplete pin, read failure)
/// is `None` -> fail-closed to online recovery. Extracted from `handle_confirm_request` so the
/// phone-to-chip relay wiring is exercised in-process with mock transports (Phase H0) through the
/// exact code the handler runs; the handler passes `crate::bridge::anchor_counter_reader()` as
/// `reader`.
pub(crate) async fn resolve_attested_counter(
    pin: Option<&dsm::crypto::anchor_enrollment::FusedAnchorPin>,
    reader: Option<std::sync::Arc<dyn crate::bluetooth::tropic_relay::AnchorCounterReader>>,
    sender_device_id: [u8; 32],
    commitment_hash: [u8; 32],
) -> Option<([u8; 32], u64)> {
    let p = pin.filter(|p| pin_ready_for_counter_read(p))?;
    let reader = reader?;
    reader
        .read_counter(sender_device_id, commitment_hash, p.clone())
        .await
        .map(|h| (p.anchor_id, u64::from(h)))
}

/// Test-only stand-in for the D2 receiver-operated authenticated L3 counter session. It returns the
/// counter an authentic verifier session WOULD attest — `H = H₀ − (uᵢ+1)`, computed from the pinned
/// enrolled counter and the transition's `next_anchor_counter` — so the full producer → accept →
/// adopt chain can be exercised. It is NOT wired into the production [`accept_offline_release`];
/// live accept keeps [`DsmCounterVerifier`] and stays fail-closed until the real L3 verifier lands.
#[cfg(test)]
pub(crate) struct TrustedTestCounter;

#[cfg(test)]
impl CounterVerifier for TrustedTestCounter {
    fn read_authentic_counter(&self, _anchor_id: &[u8; 32], ev: &CounterEvidence) -> Option<u64> {
        ev.enrolled_counter
            .checked_sub(ev.derived_anchor_counter_claim)
    }
}

/// The holder's successor appliance-lineage state, returned on acceptance so the
/// receiver can ADOPT it (persist as the new accepted root) once the canonical
/// commit succeeds. Def. 25 check 2 then pins the NEXT release's `prev_root` to
/// this frontier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdoptedAnchorState {
    /// The release's `next_root` — the appliance root the next transfer consumes.
    pub next_root: [u8; 32],
    /// The release's `next_anchor_counter` (`uᵢ + 1`) adopted with it.
    pub next_anchor_counter: u64,
}

/// Apply the canonical Boot Fenced Fused Anchor acceptance predicate to an inbound
/// offline-bearer confirm. Fail-closed: returns `Err(OfflineRecover)` (release no value,
/// recover online) on a missing/malformed release, an un-enrolled anchor, or ANY failed
/// predicate check — including the unauthenticated counter. On `Ok(adopted)` the receiver
/// may proceed to the canonical value-release commit, and after that commit succeeds must
/// persist `adopted` as the holder's accepted appliance root.
///
/// `accepted_prev_root`: the appliance root adopted from the holder's last accepted
/// release. `None` = relationship genesis (nothing adopted yet) — the release's own
/// `prev_root` is adopted TOFU; its authenticity still rests on the anchor-state
/// commitment proofs (checks 3–4) and the live authenticated counter (checks 17–19),
/// the same trust root as the first-transfer pin admit.
#[allow(clippy::too_many_arguments)]
pub fn accept_offline_release(
    offline_release: &[u8],
    pinned: Option<&PinnedAnchor>,
    accepted_prev_root: Option<&[u8; 32]>,
    receiver_device_id: &[u8; 32],
    expected_receiver_challenge: &[u8; 32],
    expected_policy_hash: &[u8; 32],
    binding: &AnchorStateBinding,
) -> Result<AdoptedAnchorState, OfflineRecover> {
    // Canonical production path: the Path-B authenticated-counter verifier is fail-closed until the
    // async raw-SPI relay read is wired into the receiver (D2 step 5). With `attested = None` the
    // predicate fails on the counter clause and the transfer recovers online. The live-relay path
    // (`accept_offline_release_with_relay_counter`) constructs a populated verifier instead.
    accept_offline_release_with_counter(
        offline_release,
        pinned,
        accepted_prev_root,
        receiver_device_id,
        expected_receiver_challenge,
        expected_policy_hash,
        binding,
        &DsmCounterVerifier::fail_closed(),
    )
}

/// Path-B live-relay acceptance: identical to [`accept_offline_release`] but supplied the counter
/// `H` the receiver ALREADY read from the holder's TROPIC01 over its own authenticated libtropic-rs
/// session (via the raw-SPI relay), tagged with the `anchor_id` it was read from. The predicate then
/// enforces `H == H0 - (u_i + 1)` exactly (anchor-core check 19). Pass `attested = None` to stay
/// fail-closed (no verifier slot / no live relay / read failed).
#[allow(clippy::too_many_arguments)]
pub fn accept_offline_release_with_relay_counter(
    offline_release: &[u8],
    pinned: Option<&PinnedAnchor>,
    accepted_prev_root: Option<&[u8; 32]>,
    receiver_device_id: &[u8; 32],
    expected_receiver_challenge: &[u8; 32],
    expected_policy_hash: &[u8; 32],
    binding: &AnchorStateBinding,
    attested: Option<([u8; 32], u64)>,
) -> Result<AdoptedAnchorState, OfflineRecover> {
    accept_offline_release_with_counter(
        offline_release,
        pinned,
        accepted_prev_root,
        receiver_device_id,
        expected_receiver_challenge,
        expected_policy_hash,
        binding,
        &DsmCounterVerifier { attested },
    )
}

/// Counter-verifier-injectable form of [`accept_offline_release`]. The production wrapper pins the
/// fail-closed [`DsmCounterVerifier`]; the activation integration test injects a stub that stands in
/// for the (not-yet-built, D2) receiver-operated authenticated L3 counter session, so the full
/// producer → accept → adopt chain can be exercised without weakening the live path.
#[allow(clippy::too_many_arguments)]
pub(crate) fn accept_offline_release_with_counter<C: CounterVerifier>(
    offline_release: &[u8],
    pinned: Option<&PinnedAnchor>,
    accepted_prev_root: Option<&[u8; 32]>,
    receiver_device_id: &[u8; 32],
    expected_receiver_challenge: &[u8; 32],
    expected_policy_hash: &[u8; 32],
    binding: &AnchorStateBinding,
    counter: &C,
) -> Result<AdoptedAnchorState, OfflineRecover> {
    if offline_release.is_empty() {
        // Absent canonical release (or a legacy IslandAttestation-only confirm).
        return Err(OfflineRecover::MissingRelease);
    }
    let rel = pb::OfflineRelease::decode(offline_release)
        .map_err(|_| OfflineRecover::Malformed)?
        .to_release()
        .map_err(|_| OfflineRecover::Malformed)?;
    let pinned = pinned.ok_or(OfflineRecover::AnchorNotEnrolled)?;

    // Def. 25 check 2 root: the adopted lineage frontier when one exists,
    // else (relationship genesis) the release's own `prev_root` — TOFU,
    // still bound to the pinned chip by checks 3–4 + the live counter.
    let t = rel.transition.as_transition();
    let effective_prev_root: [u8; 32] = match accepted_prev_root {
        Some(r) => *r,
        None => *t.prev_root,
    };
    let adopted = AdoptedAnchorState {
        next_root: *t.next_root,
        next_anchor_counter: t.next_anchor_counter,
    };

    let ctx = VerifierContext {
        accepted_prev_root: &effective_prev_root,
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
        binding,
    };
    accept_offline::<WotsBlake3, _, _>(&rel, &ctx, &dsm, counter)
        .map_err(OfflineRecover::Predicate)?;
    Ok(adopted)
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

    /// A zero/empty anchor-state binding — a valid inclusion proof can never verify against a zero
    /// root with an empty proof, so the fused-anchor-state checks stay fail-closed.
    const ZB: AnchorStateBinding<'static> = AnchorStateBinding {
        sender_smt_root: &ZERO,
        sender_smt_root_before: &ZERO,
        prev_proof: &[],
        next_proof: &[],
    };

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
        let r = accept_offline_release(&[], Some(&pin()), Some(&ZERO), &ZERO, &ZERO, &ZERO, &ZB);
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
        let r = accept_offline_release(&bytes, Some(&pin()), Some(&ZERO), &ZERO, &ZERO, &ZERO, &ZB);
        assert!(matches!(r, Err(OfflineRecover::Malformed)));
    }

    #[test]
    fn unenrolled_anchor_routes_online() {
        // A decodable release with NO pinned anchor (the live Phase-4 seam) recovers online.
        let bytes = decodable_release_bytes();
        let r = accept_offline_release(&bytes, None, Some(&ZERO), &ZERO, &ZERO, &ZERO, &ZB);
        assert!(matches!(r, Err(OfflineRecover::AnchorNotEnrolled)));
    }

    #[test]
    fn predicate_rejects_and_routes_online() {
        // A decodable release WITH a pin reaches accept_offline and is rejected by the predicate
        // (proves the canonical predicate is wired and fail-closed — it can never accept here).
        let bytes = decodable_release_bytes();
        let r = accept_offline_release(&bytes, Some(&pin()), Some(&ZERO), &ZERO, &ZERO, &ZERO, &ZB);
        assert!(matches!(r, Err(OfflineRecover::Predicate(_))));
    }

    #[test]
    fn counter_verifier_uses_pre_read_counter_never_host_claim() {
        // Host-supplied claims are always present in the evidence; the verifier must NEVER echo them.
        let ev = CounterEvidence {
            anchor_id: ZERO,
            enrolled_counter: 100,
            live_counter_claim: 99,             // host says H = 99
            derived_anchor_counter_claim: 1,    // host says u = 1
            verifier_transcript: vec![1, 2, 3], // even a populated transcript must not be trusted here
        };

        // Fail-closed default: no authenticated relay read -> None, regardless of the host claims.
        let v = DsmCounterVerifier::fail_closed();
        assert_eq!(v.read_authentic_counter(&ZERO, &ev), None);

        // With a pre-read authentic counter for the matching anchor: return THAT value (42), never
        // the host's live_counter_claim (99).
        let anchor = [0xA7u8; 32];
        let v = DsmCounterVerifier {
            attested: Some((anchor, 42)),
        };
        assert_eq!(v.read_authentic_counter(&anchor, &ev), Some(42));

        // A counter read from a DIFFERENT anchor is not evidence for this one -> fail closed.
        assert_eq!(v.read_authentic_counter(&ZERO, &ev), None);
    }

    #[test]
    fn state_verifier_anchor_state_fails_closed_on_empty_binding() {
        let rid = [7u8; 32];
        let pk = vec![0u8; 64];
        let v = DsmStateVerifier {
            receiver_device_id: &rid,
            partition_pk: &pk,
            binding: &ZB,
        };
        // A zero device root + empty proof can never satisfy the fused-anchor-state inclusion —
        // the receiver fails closed when the producer did not carry real anchor-state proofs.
        assert!(!v.prev_root_commits_anchor_state(&ZERO, &ZERO, &ZERO, &ZERO, 0));
        assert!(!v.next_root_commits_anchor_state(&ZERO, &ZERO, &ZERO, &ZERO, 1));
    }

    /// The fused-anchor-state binding accepts a REAL inclusion proof produced by
    /// `DeviceState::advance` and rejects wrong roots / off-by-one state — the receiver-side half
    /// of the §12 binding, exercised end-to-end against the actual SparseMerkleTree.
    #[test]
    fn state_verifier_accepts_real_anchor_state_proof_and_rejects_tamper() {
        use dsm::core::bilateral_transaction_manager::set_anchor_state_leaf;
        let b = [0xB1u8; 32];
        let (a, j, u) = ([0xA1u8; 32], [0x51u8; 32], 3u64);
        // Build a device SMT that commits the fused state, and take a real inclusion proof.
        let mut smt = dsm::merkle::sparse_merkle_tree::SparseMerkleTree::new(256);
        let proof = set_anchor_state_leaf(&mut smt, &b, &a, &j, u).expect("leaf");
        let root = *smt.root();

        let rid = [7u8; 32];
        let pk = vec![0u8; 64];
        let binding = AnchorStateBinding {
            sender_smt_root: &root,
            sender_smt_root_before: &root,
            prev_proof: &proof,
            next_proof: &proof,
        };
        let v = DsmStateVerifier {
            receiver_device_id: &rid,
            partition_pk: &pk,
            binding: &binding,
        };
        // Accepts the exact fused state under the committing root.
        assert!(v.prev_root_commits_anchor_state(&ZERO, &b, &a, &j, u));
        assert!(v.next_root_commits_anchor_state(&ZERO, &b, &a, &j, u));
        // Off-by-one counter / wrong head reject.
        assert!(!v.prev_root_commits_anchor_state(&ZERO, &b, &a, &j, u + 1));
        assert!(!v.next_root_commits_anchor_state(&ZERO, &b, &[0u8; 32], &j, u));
    }

    // ------------------------------------------------------------------
    // Receiver-admit fold: pin_admit_decision matrix + the admission-never-
    // implies-acceptance invariant.
    // ------------------------------------------------------------------

    fn fused_pin(
        slot: Option<u8>,
        stpub: Option<[u8; 32]>,
    ) -> dsm::crypto::anchor_enrollment::FusedAnchorPin {
        dsm::crypto::anchor_enrollment::FusedAnchorPin {
            bundle: [0xB1; 32],
            anchor_id: [0xA1; 32],
            enrolled_counter: 1_000_000,
            partition_pk: vec![0x07; 64],
            uncompromised: true,
            verifier_slot: slot,
            chip_static_pubkey: stpub,
        }
    }

    fn pinned(
        slot: Option<u8>,
        stpub: Option<[u8; 32]>,
    ) -> dsm::crypto::anchor_enrollment::AnchorEnrollment {
        dsm::crypto::anchor_enrollment::AnchorEnrollment {
            device_id: [0x11; 32],
            policy_hash: [0x9A; 32],
            pin: fused_pin(slot, stpub),
        }
    }

    #[test]
    fn pin_admit_decision_first_transfer_admits_under_disclosed_policy() {
        let d = fused_pin(None, None);
        match pin_admit_decision([0x11; 32], [0x9A; 32], &d, None) {
            PinAdmitDecision::Admit(e) => {
                assert_eq!(e.device_id, [0x11; 32]);
                assert_eq!(e.policy_hash, [0x9A; 32]);
                assert_eq!(e.pin.anchor_id, [0xA1; 32]);
                assert!(e.pin.uncompromised, "admission sets uncompromised=true");
                assert_eq!(e.pin.verifier_slot, None, "pre-HW admit is incomplete");
            }
            other => panic!("expected Admit, got {other:?}"),
        }
    }

    #[test]
    fn pin_admit_decision_upgrades_incomplete_pin_and_preserves_compromise_flag() {
        // The pre-HW pin lacks slot+stpub; a later disclosure for the SAME anchor supplies them.
        let mut cur = pinned(None, None);
        cur.pin.uncompromised = false; // a disclosure must never resurrect a compromised anchor
        let d = fused_pin(Some(2), Some([0xCC; 32]));
        match pin_admit_decision([0x11; 32], [0x9A; 32], &d, Some(&cur)) {
            PinAdmitDecision::Upgrade(e) => {
                assert_eq!(e.pin.verifier_slot, Some(2));
                assert_eq!(e.pin.chip_static_pubkey, Some([0xCC; 32]));
                assert!(!e.pin.uncompromised, "existing compromise flag preserved");
                assert_eq!(e.policy_hash, [0x9A; 32], "existing policy preserved");
            }
            other => panic!("expected Upgrade, got {other:?}"),
        }
    }

    #[test]
    fn pin_admit_decision_no_change_when_disclosure_adds_nothing() {
        let cur = pinned(Some(2), Some([0xCC; 32]));
        let d = fused_pin(Some(2), Some([0xCC; 32]));
        assert_eq!(
            pin_admit_decision([0x11; 32], [0x9A; 32], &d, Some(&cur)),
            PinAdmitDecision::NoChange
        );
        // Re-disclosing the incomplete shape against a complete pin also changes nothing.
        let d = fused_pin(None, None);
        assert_eq!(
            pin_admit_decision([0x11; 32], [0x9A; 32], &d, Some(&cur)),
            PinAdmitDecision::NoChange
        );
    }

    #[test]
    fn pin_admit_decision_rejects_every_conflicting_disclosure() {
        let cur = pinned(Some(2), Some([0xCC; 32]));
        let base = fused_pin(Some(2), Some([0xCC; 32]));

        let mut anchor = base.clone();
        anchor.anchor_id = [0xEE; 32]; // changed anchor id after pinning = substitution attack
        let mut bundle = base.clone();
        bundle.bundle = [0xEE; 32];
        let mut h0 = base.clone();
        h0.enrolled_counter = 999_999;
        let mut part = base.clone();
        part.partition_pk = vec![0x08; 64];
        let mut stpub = base.clone();
        stpub.chip_static_pubkey = Some([0xDD; 32]);
        let mut slot = base.clone();
        slot.verifier_slot = Some(3);

        for d in [&anchor, &bundle, &h0, &part, &stpub, &slot] {
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

    /// THE invariant: admission never implies acceptance. An incomplete pin (as admitted on the
    /// pre-HW first transfer) is never counter-read — `pin_ready_for_counter_read` gates the
    /// handler BEFORE any installed reader — so even a reader that would (wrongly) return the
    /// exactly-correct counter cannot produce `attested = Some`, and the predicate fails closed
    /// to online recovery exactly as with no reader at all.
    #[test]
    fn incomplete_pin_is_never_counter_read_even_with_a_reader_that_would_answer() {
        let incomplete = fused_pin(None, None);
        assert!(!pin_ready_for_counter_read(&incomplete));
        let slot_only = fused_pin(Some(2), None);
        assert!(!pin_ready_for_counter_read(&slot_only));
        let stpub_only = fused_pin(None, Some([0xCC; 32]));
        assert!(!pin_ready_for_counter_read(&stpub_only));
        let mut compromised = fused_pin(Some(2), Some([0xCC; 32]));
        compromised.uncompromised = false;
        assert!(!pin_ready_for_counter_read(&compromised));
        let complete = fused_pin(Some(2), Some([0xCC; 32]));
        assert!(pin_ready_for_counter_read(&complete));

        // Mirror the handler seam byte-for-byte: a stub "reader" that would answer with the
        // exactly-correct counter is unreachable behind the gate, so attested stays None...
        let would_be_correct_h: u64 = 999_999;
        let reader = |_pin: &dsm::crypto::anchor_enrollment::FusedAnchorPin| {
            Some((incomplete.anchor_id, would_be_correct_h))
        };
        let attested: Option<([u8; 32], u64)> = Some(&incomplete)
            .filter(|p| pin_ready_for_counter_read(p))
            .and_then(reader);
        assert_eq!(attested, None, "incomplete pin must never be counter-read");

        // ...and with attested=None the counter verifier refuses, so the 22-check predicate can
        // never see an authentic counter: acceptance is impossible, online recovery only.
        let v = DsmCounterVerifier { attested };
        let ev = CounterEvidence {
            anchor_id: incomplete.anchor_id,
            enrolled_counter: 1_000_000,
            live_counter_claim: would_be_correct_h, // host claims are never trusted
            derived_anchor_counter_claim: 1,
            verifier_transcript: Vec::new(),
        };
        assert_eq!(v.read_authentic_counter(&incomplete.anchor_id, &ev), None);
    }
}
