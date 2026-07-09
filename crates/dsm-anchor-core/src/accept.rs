//! The v2 receiver acceptance predicate (§13, Def. 12) — Software Authority, Hardware
//! Identity. An honest receiver accepts an offline root advance iff every check below
//! holds. Acceptance verifies **software objects only**: the three signatures over
//! `M_{i+1}` (`σ^DSM` seed, `σ^chip` resident-chip, `σ^host` partition), the device-SMT
//! inclusion proofs `Π_i`/`Π_{i+1}`, the forward-only frontier (directly or via a
//! `BranchProof`), the challenge, the recipient, the checked counter increment, and — at
//! genesis — the upgrade certificate. **No step reads hardware.** There is no verify-live
//! and no optional audit path: the verifier has no live-hardware dependency — it verifies
//! signed identity evidence (`σ^chip`/`σ^host`) against the public keys enrolled in `B`.
//! Removing the live hardware checks does not remove the chip and host witness requirements
//! (§ Corollary 1).
//!
//! Uniqueness is a software property of the DSM device SMT: one parent root `R_i` admits
//! at most one accepted successor per receiver (the adopted frontier is forward-only, so a
//! later release claiming an already-consumed frontier is rejected on sight). Cross-receiver
//! forks are position collisions exposed by Tripwire on reconciliation, not prevented here.

use crate::root_advance::{
    anchor_root_advance, anchor_state_leaf, root_advance_message, transition_digest, Certificate,
    OfflineRelease,
};
use crate::tropic::{ChipSig, PartitionSig};
use crate::util::ct_eq_32;

/// The DSM-state verifier the receiver supplies. The device SMT is the software authority;
/// these checks are implemented by the dsm layer (SMT inclusion + DSM transition validity,
/// the latter carrying `σ^DSM`).
pub trait DsmVerifier {
    /// The device SMT `root` commits the anchor-state `leaf` (`= H(B ‖ h ‖ u)`) via `proof`.
    fn verify_smt_leaf(&self, root: &[u8; 32], proof: &[u8], leaf: &[u8; 32]) -> bool;
    /// The DSM transition (`σ^DSM` + whole-state consumption `R_i → R_{i+1}`) verifies. The
    /// transition is located by its canonical digest `D` plus the frontier pair so the dsm
    /// layer can check it without re-borrowing the wire `Transition`.
    fn verify_transition(
        &self,
        transition_digest: &[u8; 32],
        prev_root: &[u8; 32],
        next_root: &[u8; 32],
    ) -> bool;
    /// The transfer delivers the claimed object/value to this receiver.
    fn delivers_to_receiver(&self, transition_digest: &[u8; 32], recipient: &[u8; 32]) -> bool;
    /// At genesis (first transfer to this holder) the upgrade certificate binds `I_off` to
    /// `I_on` under the online identity's own signature.
    fn verify_upgrade_cert(&self, bundle: &[u8; 32]) -> bool;
}

/// Receiver-side pinned/supplied context.
pub struct VerifierContext<'a> {
    /// The enrolled anchor bundle `B` this receiver pinned.
    pub pinned_bundle: &'a [u8; 32],
    /// The enrolled TROPIC01 anchor identity this receiver pinned.
    pub pinned_anchor_id: &'a [u8; 32],
    /// The resident chip public key `pk_chip`, pinned in `B` at enrollment.
    pub pinned_pk_chip: &'a [u8],
    /// The RP2350 partition public key `pk_host`, pinned in `B` at enrollment.
    pub pinned_pk_host: &'a [u8],
    /// The offline frontier root this receiver has adopted for this holder (or genesis `h_0`).
    pub accepted_frontier: &'a [u8; 32],
    /// The receiver challenge `r_R` this receiver supplied.
    pub expected_receiver_challenge: &'a [u8; 32],
    /// This receiver's device id — the release must name it as the recipient.
    pub expected_recipient: &'a [u8; 32],
    /// The authority policy hash bound to the previous state.
    pub expected_policy_hash: &'a [u8; 32],
    /// `true` iff no firmware-boundary / physical-compromise / policy event invalidates the anchor.
    pub anchor_uncompromised: bool,
    /// `true` for the first transfer to this holder (requires the upgrade certificate).
    pub is_genesis: bool,
}

/// Which Def. 12 check failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AcceptError {
    /// Δ / Cert / bundle / anchor describe different advances.
    NonCanonical,
    /// The release does not chain from the receiver's adopted frontier (no valid BranchProof).
    FrontierNotAccepted,
    /// `Π_i` does not prove `R_i` commits `(B, h_i, u_i)`.
    PrevStateUncommitted,
    /// `u_{i+1} != u_i + 1`.
    BadNextAnchorCounter,
    /// Receiver challenge mismatch.
    ChallengeMismatch,
    /// The release does not name this receiver as the recipient.
    RecipientMismatch,
    /// `D_{i+1}` does not recompute from Δ°.
    DigestMismatch,
    /// `h_{i+1}` does not recompute as `H(h_i ‖ D_{i+1})`.
    FrontierMismatch,
    /// `M_{i+1}` does not recompute from the bound fields.
    MessageMismatch,
    /// `ChipVerify(pk_chip, M, σ^chip) = 0` — missing/invalid chip signature.
    ChipSigInvalid,
    /// `HostVerify(pk_host, M, σ^host) = 0` — missing/invalid host signature.
    HostSigInvalid,
    /// The DSM transition (`σ^DSM` + `R_i → R_{i+1}`) is invalid.
    TransitionProofInvalid,
    /// Transfer not delivered to this receiver.
    NotDeliveredToReceiver,
    /// `Π_{i+1}` does not prove `R_{i+1}` commits `(B, h_{i+1}, u_i+1)`.
    NextStateUncommitted,
    /// Authority policy hash mismatch.
    PolicyMismatch,
    /// Genesis upgrade certificate invalid.
    UpgradeCertInvalid,
    /// Anchor invalidated by a firmware/physical/policy event.
    AnchorCompromised,
    /// A BranchProof hop does not chain / verify.
    BranchProofInvalid,
}

/// Recompute `h_{i+1}` and `M_{i+1}` from a certificate's own carried fields and verify the
/// chip + host signatures over that `M`. Works for the accepted release AND for each
/// `BranchProof` hop — a hop carries its own `transition_digest`, so no `Δ` is needed. Note
/// this does NOT recompute `D` from `Δ°`; that Δ°-binding check is done once, on the accepted
/// release only, in [`accept_offline`].
fn verify_cert_frontier_and_sigs<C: ChipSig, P: PartitionSig>(
    cert: &Certificate,
    pk_chip: &[u8],
    pk_host: &[u8],
) -> Result<(), AcceptError> {
    let h_next = anchor_root_advance(&cert.prev_frontier, &cert.transition_digest);
    if !ct_eq_32(&h_next, &cert.next_frontier) {
        return Err(AcceptError::FrontierMismatch);
    }
    let m = root_advance_message(
        &cert.anchor_bundle,
        &cert.sender_device_root_before,
        &cert.sender_device_root_after,
        &cert.prev_frontier,
        &cert.next_frontier,
        cert.anchor_counter,
        cert.next_anchor_counter,
        &cert.transition_digest,
        &cert.recipient,
        &cert.receiver_challenge,
    );
    if !ct_eq_32(&m, &cert.root_advance_message) {
        return Err(AcceptError::MessageMismatch);
    }
    if !C::verify(pk_chip, &m, &cert.sigma_chip) {
        return Err(AcceptError::ChipSigInvalid);
    }
    if !P::part_verify(pk_host, &m, &cert.sigma_host) {
        return Err(AcceptError::HostSigInvalid);
    }
    Ok(())
}

/// `Accept_off(Pkg) = 1` iff every Def. 12 check holds. Returns the first failing check.
///
/// `C` verifies the resident-chip signature (`σ^chip`); `P` verifies the partition
/// signature (`σ^host`). The seed-derived `σ^DSM` is verified inside `dsm.verify_transition`
/// (it is the ordinary DSM transition signature, factor one). No hardware is touched.
pub fn accept_offline<D, C, P>(
    rel: &OfflineRelease,
    ctx: &VerifierContext,
    dsm: &D,
) -> Result<(), AcceptError>
where
    D: DsmVerifier,
    C: ChipSig,
    P: PartitionSig,
{
    let t = rel.transition.as_transition();
    let cert = &rel.cert;

    // (1) Δ, Cert, bundle, anchor describe the same advance.
    if !ct_eq_32(&cert.prev_frontier, t.prev_root)
        || !ct_eq_32(&cert.next_frontier, t.next_root)
        || cert.anchor_counter != t.anchor_counter
        || cert.next_anchor_counter != t.next_anchor_counter
        || !ct_eq_32(&cert.anchor_bundle, ctx.pinned_bundle)
        || !ct_eq_32(&cert.anchor_id, ctx.pinned_anchor_id)
        || !ct_eq_32(&cert.recipient, t.recipient_device_id)
    {
        return Err(AcceptError::NonCanonical);
    }

    // (2) The release chains from the receiver's adopted frontier — directly, or via a
    // verifying BranchProof (Def. 10). Each hop is a prior self-consistent cert whose
    // next_frontier chains forward; the walk must reach `cert.prev_frontier` starting from
    // the adopted frontier. A release claiming an already-consumed frontier fails here.
    if !ct_eq_32(&cert.prev_frontier, ctx.accepted_frontier) {
        let mut cursor = *ctx.accepted_frontier;
        for hop in &rel.branch_proof {
            if !ct_eq_32(&hop.prev_frontier, &cursor) {
                return Err(AcceptError::BranchProofInvalid);
            }
            verify_cert_frontier_and_sigs::<C, P>(hop, ctx.pinned_pk_chip, ctx.pinned_pk_host)
                .map_err(|_| AcceptError::BranchProofInvalid)?;
            cursor = hop.next_frontier;
        }
        if !ct_eq_32(&cursor, &cert.prev_frontier) {
            return Err(AcceptError::FrontierNotAccepted);
        }
    }

    // (3) Π_i proves R_i commits the anchor-state leaf (B, h_i, u_i).
    let leaf_i = anchor_state_leaf(ctx.pinned_bundle, &cert.prev_frontier, cert.anchor_counter);
    if !dsm.verify_smt_leaf(
        &cert.sender_device_root_before,
        &rel.anchor_smt_proof_before,
        &leaf_i,
    ) {
        return Err(AcceptError::PrevStateUncommitted);
    }

    // (4) u_{i+1} = u_i + 1 (checked).
    if t.anchor_counter.checked_add(1) != Some(t.next_anchor_counter) {
        return Err(AcceptError::BadNextAnchorCounter);
    }

    // (5) Receiver challenge matches.
    if !ct_eq_32(&cert.receiver_challenge, ctx.expected_receiver_challenge) {
        return Err(AcceptError::ChallengeMismatch);
    }

    // (6) Recipient names this receiver.
    if !ct_eq_32(&cert.recipient, ctx.expected_recipient) {
        return Err(AcceptError::RecipientMismatch);
    }

    // (7) D_{i+1} recomputes from Δ° (the core, excluding the successor root). This binds the
    // carried digest to the full transition; done only here, on the accepted release.
    let d = transition_digest(&t, &cert.receiver_challenge);
    if !ct_eq_32(&d, &cert.transition_digest) {
        return Err(AcceptError::DigestMismatch);
    }

    // (8-11) h_{i+1} = H(h_i ‖ D), M recomputes, and the chip + host signatures verify.
    verify_cert_frontier_and_sigs::<C, P>(cert, ctx.pinned_pk_chip, ctx.pinned_pk_host)?;

    // (12) DSM transition (σ^DSM + R_i → R_{i+1}).
    if !dsm.verify_transition(
        &cert.transition_digest,
        &cert.prev_frontier,
        &cert.next_frontier,
    ) {
        return Err(AcceptError::TransitionProofInvalid);
    }

    // (13) Delivered to this receiver.
    if !dsm.delivers_to_receiver(&cert.transition_digest, &cert.recipient) {
        return Err(AcceptError::NotDeliveredToReceiver);
    }

    // (14) Π_{i+1} proves R_{i+1} commits (B, h_{i+1}, u_i+1).
    let leaf_next = anchor_state_leaf(
        ctx.pinned_bundle,
        &cert.next_frontier,
        cert.next_anchor_counter,
    );
    if !dsm.verify_smt_leaf(
        &cert.sender_device_root_after,
        &rel.anchor_smt_proof_after,
        &leaf_next,
    ) {
        return Err(AcceptError::NextStateUncommitted);
    }

    // (15) Authority policy hash matches the previous state.
    if !ct_eq_32(t.authority_policy_hash, ctx.expected_policy_hash) {
        return Err(AcceptError::PolicyMismatch);
    }

    // (16) Genesis adoption: the upgrade certificate binds I_off to I_on.
    if ctx.is_genesis && !dsm.verify_upgrade_cert(ctx.pinned_bundle) {
        return Err(AcceptError::UpgradeCertInvalid);
    }

    // (17) No firmware-boundary / physical-compromise / policy event.
    if !ctx.anchor_uncompromised {
        return Err(AcceptError::AnchorCompromised);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::hash::h;
    use crate::root_advance::OwnedTransition;
    use alloc::vec::Vec;

    // --- deterministic mock signature schemes (host-only; no chip touched) ---

    /// Mock resident-chip signature: `σ^chip = H("mock/chip" ‖ pk_chip ‖ M)`.
    struct MockChip;
    impl ChipSig for MockChip {
        fn verify(pk_chip: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
            sig == h("mock/chip", &[pk_chip, message])
        }
    }
    fn chip_sign(pk_chip: &[u8], m: &[u8; 32]) -> Vec<u8> {
        h("mock/chip", &[pk_chip, m]).to_vec()
    }

    /// Mock partition (`σ^host`) scheme: keygen derives `pk = H("mock/hostpk" ‖ seed)`,
    /// sign/verify use `H("mock/host" ‖ pk ‖ M)`.
    struct MockHost;
    impl PartitionSig for MockHost {
        fn part_keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
            let pk = h("mock/hostpk", &[seed]).to_vec();
            (seed.to_vec(), pk)
        }
        fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Vec<u8> {
            let pk = h("mock/hostpk", &[sk]).to_vec();
            h("mock/host", &[&pk, digest]).to_vec()
        }
        fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
            sig == h("mock/host", &[pk, digest])
        }
    }
    fn host_sign(pk_host: &[u8], m: &[u8; 32]) -> Vec<u8> {
        h("mock/host", &[pk_host, m]).to_vec()
    }

    /// Mock DSM verifier: every software check configurable; SMT/transition true by default.
    struct MockDsm {
        transition_ok: bool,
        delivery_ok: bool,
        smt_ok: bool,
        upgrade_ok: bool,
    }
    impl Default for MockDsm {
        fn default() -> Self {
            Self {
                transition_ok: true,
                delivery_ok: true,
                smt_ok: true,
                upgrade_ok: true,
            }
        }
    }
    impl DsmVerifier for MockDsm {
        fn verify_smt_leaf(&self, _r: &[u8; 32], _p: &[u8], _l: &[u8; 32]) -> bool {
            self.smt_ok
        }
        fn verify_transition(&self, _d: &[u8; 32], _p: &[u8; 32], _n: &[u8; 32]) -> bool {
            self.transition_ok
        }
        fn delivers_to_receiver(&self, _d: &[u8; 32], _r: &[u8; 32]) -> bool {
            self.delivery_ok
        }
        fn verify_upgrade_cert(&self, _b: &[u8; 32]) -> bool {
            self.upgrade_ok
        }
    }

    const B: [u8; 32] = [0x11; 32];
    const ANCHOR_ID: [u8; 32] = [0x22; 32];
    const PK_CHIP: [u8; 32] = [0x33; 32];
    const PK_HOST: [u8; 32] = [0x44; 32];
    const RECIPIENT: [u8; 32] = [0x55; 32];
    const R_CHALLENGE: [u8; 32] = [0x66; 32];
    const POLICY: [u8; 32] = [0x77; 32];
    const H0: [u8; 32] = [0x88; 32]; // genesis frontier

    /// Build a fully valid release advancing from `prev_frontier` at counter `u`.
    fn valid_release(prev_frontier: [u8; 32], u: u64) -> OfflineRelease {
        let next_u = u + 1;
        let mut owned = OwnedTransition {
            relationship_id: [0x04; 32],
            object_id: [0x01; 32],
            sender_device_id: [0x02; 32],
            recipient_device_id: RECIPIENT,
            prev_root: prev_frontier,
            next_root: [0u8; 32], // filled below once h_{i+1} is known
            anchor_counter: u,
            next_anchor_counter: next_u,
            action_type: 1,
            action_fields: Vec::new(),
            payload_hash: [0x03; 32],
            old_leaf_proof: alloc::vec![0xAA],
            new_leaf_proof: alloc::vec![0xBB],
            authority_policy_hash: POLICY,
        };

        // D over Δ° — Δ° excludes next_root, so computing D before next_root is set is exact
        // (this is the DAG property that kills the digest fixed point).
        let d = transition_digest(&owned.as_transition(), &R_CHALLENGE);
        let h_next = anchor_root_advance(&prev_frontier, &d);
        owned.next_root = h_next;

        let r_before = h(
            "mock/root-before",
            &[&B, &prev_frontier, &u64::to_le_bytes(u)],
        );
        let r_after = h("mock/root-after", &[&B, &h_next, &u64::to_le_bytes(next_u)]);
        let m = root_advance_message(
            &B,
            &r_before,
            &r_after,
            &prev_frontier,
            &h_next,
            u,
            next_u,
            &d,
            &RECIPIENT,
            &R_CHALLENGE,
        );

        let cert = Certificate {
            anchor_bundle: B,
            sender_device_root_before: r_before,
            sender_device_root_after: r_after,
            prev_frontier,
            next_frontier: h_next,
            anchor_counter: u,
            next_anchor_counter: next_u,
            transition_digest: d,
            root_advance_message: m,
            anchor_id: ANCHOR_ID,
            sigma_chip: chip_sign(&PK_CHIP, &m),
            sigma_host: host_sign(&PK_HOST, &m),
            receiver_challenge: R_CHALLENGE,
            recipient: RECIPIENT,
        };

        OfflineRelease {
            transition: owned,
            anchor_smt_proof_before: alloc::vec![0xCC],
            anchor_smt_proof_after: alloc::vec![0xDD],
            cert,
            branch_proof: Vec::new(),
        }
    }

    fn ctx(accepted_frontier: &[u8; 32]) -> VerifierContext<'_> {
        VerifierContext {
            pinned_bundle: &B,
            pinned_anchor_id: &ANCHOR_ID,
            pinned_pk_chip: &PK_CHIP,
            pinned_pk_host: &PK_HOST,
            accepted_frontier,
            expected_receiver_challenge: &R_CHALLENGE,
            expected_recipient: &RECIPIENT,
            expected_policy_hash: &POLICY,
            anchor_uncompromised: true,
            is_genesis: false,
        }
    }

    // (1) M binds every field: flipping any bound input changes M, and a tampered carried M
    // is rejected.
    #[test]
    fn message_binds_every_field_and_rejects_tamper() {
        let base = root_advance_message(
            &[1; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32], 6, 7, &[8; 32], &[9; 32], &[10; 32],
        );
        assert_ne!(
            base,
            root_advance_message(
                &[0; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32], 6, 7, &[8; 32], &[9; 32],
                &[10; 32]
            )
        );
        assert_ne!(
            base,
            root_advance_message(
                &[1; 32], &[0; 32], &[3; 32], &[4; 32], &[5; 32], 6, 7, &[8; 32], &[9; 32],
                &[10; 32]
            )
        );
        assert_ne!(
            base,
            root_advance_message(
                &[1; 32], &[2; 32], &[0; 32], &[4; 32], &[5; 32], 6, 7, &[8; 32], &[9; 32],
                &[10; 32]
            )
        );
        assert_ne!(
            base,
            root_advance_message(
                &[1; 32], &[2; 32], &[3; 32], &[0; 32], &[5; 32], 6, 7, &[8; 32], &[9; 32],
                &[10; 32]
            )
        );
        assert_ne!(
            base,
            root_advance_message(
                &[1; 32], &[2; 32], &[3; 32], &[4; 32], &[0; 32], 6, 7, &[8; 32], &[9; 32],
                &[10; 32]
            )
        );
        assert_ne!(
            base,
            root_advance_message(
                &[1; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32], 0, 7, &[8; 32], &[9; 32],
                &[10; 32]
            )
        );
        assert_ne!(
            base,
            root_advance_message(
                &[1; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32], 6, 0, &[8; 32], &[9; 32],
                &[10; 32]
            )
        );
        assert_ne!(
            base,
            root_advance_message(
                &[1; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32], 6, 7, &[0; 32], &[9; 32],
                &[10; 32]
            )
        );
        assert_ne!(
            base,
            root_advance_message(
                &[1; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32], 6, 7, &[8; 32], &[0; 32],
                &[10; 32]
            )
        );
        assert_ne!(
            base,
            root_advance_message(
                &[1; 32], &[2; 32], &[3; 32], &[4; 32], &[5; 32], 6, 7, &[8; 32], &[9; 32],
                &[0; 32]
            )
        );

        let mut rel = valid_release(H0, 0);
        rel.cert.root_advance_message[0] ^= 1;
        assert_eq!(
            accept_offline::<_, MockChip, MockHost>(&rel, &ctx(&H0), &MockDsm::default()),
            Err(AcceptError::MessageMismatch)
        );
    }

    // (2) A fully valid three-signature release is accepted.
    #[test]
    fn accepts_valid_release() {
        let rel = valid_release(H0, 0);
        assert_eq!(
            accept_offline::<_, MockChip, MockHost>(&rel, &ctx(&H0), &MockDsm::default()),
            Ok(())
        );
    }

    // (3) Missing / invalid DSM signature (σ^DSM rides on the DSM transition).
    #[test]
    fn rejects_missing_dsm_signature() {
        let rel = valid_release(H0, 0);
        let dsm = MockDsm {
            transition_ok: false,
            ..MockDsm::default()
        };
        assert_eq!(
            accept_offline::<_, MockChip, MockHost>(&rel, &ctx(&H0), &dsm),
            Err(AcceptError::TransitionProofInvalid)
        );
    }

    // (4) Missing / invalid chip signature.
    #[test]
    fn rejects_missing_chip_signature() {
        let mut rel = valid_release(H0, 0);
        rel.cert.sigma_chip.clear();
        assert_eq!(
            accept_offline::<_, MockChip, MockHost>(&rel, &ctx(&H0), &MockDsm::default()),
            Err(AcceptError::ChipSigInvalid)
        );
    }

    // (5) Missing / invalid host signature.
    #[test]
    fn rejects_missing_host_signature() {
        let mut rel = valid_release(H0, 0);
        rel.cert.sigma_host.clear();
        assert_eq!(
            accept_offline::<_, MockChip, MockHost>(&rel, &ctx(&H0), &MockDsm::default()),
            Err(AcceptError::HostSigInvalid)
        );
    }

    // (6) Wrong pinned pk_chip or pk_host.
    #[test]
    fn rejects_wrong_pinned_keys() {
        let rel = valid_release(H0, 0);
        let wrong = [0xEE; 32];

        let mut c = ctx(&H0);
        c.pinned_pk_chip = &wrong;
        assert_eq!(
            accept_offline::<_, MockChip, MockHost>(&rel, &c, &MockDsm::default()),
            Err(AcceptError::ChipSigInvalid)
        );

        let mut c = ctx(&H0);
        c.pinned_pk_host = &wrong;
        assert_eq!(
            accept_offline::<_, MockChip, MockHost>(&rel, &c, &MockDsm::default()),
            Err(AcceptError::HostSigInvalid)
        );
    }

    // (7) u_{i+1} != u_i + 1 — build a consistent-but-illegal signed pair (u, u+2) so the
    // rejection is the increment guard, not the M recompute.
    #[test]
    fn rejects_bad_counter_increment() {
        let mut rel = valid_release(H0, 0);
        let u = rel.cert.anchor_counter;
        let bad_next = u + 2;
        rel.transition.next_anchor_counter = bad_next;
        rel.cert.next_anchor_counter = bad_next;
        let m = root_advance_message(
            &rel.cert.anchor_bundle,
            &rel.cert.sender_device_root_before,
            &rel.cert.sender_device_root_after,
            &rel.cert.prev_frontier,
            &rel.cert.next_frontier,
            u,
            bad_next,
            &rel.cert.transition_digest,
            &rel.cert.recipient,
            &rel.cert.receiver_challenge,
        );
        rel.cert.root_advance_message = m;
        rel.cert.sigma_chip = chip_sign(&PK_CHIP, &m);
        rel.cert.sigma_host = host_sign(&PK_HOST, &m);
        assert_eq!(
            accept_offline::<_, MockChip, MockHost>(&rel, &ctx(&H0), &MockDsm::default()),
            Err(AcceptError::BadNextAnchorCounter)
        );
    }

    // (8) Receiver challenge mismatch.
    #[test]
    fn rejects_challenge_mismatch() {
        let rel = valid_release(H0, 0);
        let other = [0x99; 32];
        let mut c = ctx(&H0);
        c.expected_receiver_challenge = &other;
        assert_eq!(
            accept_offline::<_, MockChip, MockHost>(&rel, &c, &MockDsm::default()),
            Err(AcceptError::ChallengeMismatch)
        );
    }

    // (9) Recipient mismatch.
    #[test]
    fn rejects_recipient_mismatch() {
        let rel = valid_release(H0, 0);
        let other = [0x9A; 32];
        let mut c = ctx(&H0);
        c.expected_recipient = &other;
        assert_eq!(
            accept_offline::<_, MockChip, MockHost>(&rel, &c, &MockDsm::default()),
            Err(AcceptError::RecipientMismatch)
        );
    }

    // (10) Stale frontier with no BranchProof is rejected.
    #[test]
    fn rejects_stale_frontier_without_branch_proof() {
        let rel = valid_release(H0, 0);
        let already_consumed = [0xF0; 32];
        assert_eq!(
            accept_offline::<_, MockChip, MockHost>(
                &rel,
                &ctx(&already_consumed),
                &MockDsm::default()
            ),
            Err(AcceptError::FrontierNotAccepted)
        );
    }

    // (11) Stale frontier WITH a valid BranchProof chaining adopted → cert.prev_frontier.
    #[test]
    fn accepts_stale_frontier_with_branch_proof() {
        // Receiver adopted `old`. A prior hop advanced old --(u:0→1)--> h_bridge; the current
        // release then advances from h_bridge (u:1→2). The branch proof bridges the gap.
        let old = [0xF1; 32];
        let d_hop = h("mock/hop-digest", &[&old]);
        let h_bridge = anchor_root_advance(&old, &d_hop);
        let r_b = h("mock/hop-rb", &[&old]);
        let r_a = h("mock/hop-ra", &[&h_bridge]);
        let m_hop = root_advance_message(
            &B,
            &r_b,
            &r_a,
            &old,
            &h_bridge,
            0,
            1,
            &d_hop,
            &RECIPIENT,
            &R_CHALLENGE,
        );
        let hop = Certificate {
            anchor_bundle: B,
            sender_device_root_before: r_b,
            sender_device_root_after: r_a,
            prev_frontier: old,
            next_frontier: h_bridge,
            anchor_counter: 0,
            next_anchor_counter: 1,
            transition_digest: d_hop,
            root_advance_message: m_hop,
            anchor_id: ANCHOR_ID,
            sigma_chip: chip_sign(&PK_CHIP, &m_hop),
            sigma_host: host_sign(&PK_HOST, &m_hop),
            receiver_challenge: R_CHALLENGE,
            recipient: RECIPIENT,
        };

        let mut rel = valid_release(h_bridge, 1); // current advance starts at the bridged frontier
        rel.branch_proof = alloc::vec![hop];
        assert_eq!(
            accept_offline::<_, MockChip, MockHost>(&rel, &ctx(&old), &MockDsm::default()),
            Ok(())
        );
    }

    // (12) Replay idempotence: the predicate is pure — accepting the same release twice yields
    // the same verdict and mutates nothing.
    #[test]
    fn replay_idempotence() {
        let rel = valid_release(H0, 0);
        let c = ctx(&H0);
        let dsm = MockDsm::default();
        let first = accept_offline::<_, MockChip, MockHost>(&rel, &c, &dsm);
        let second = accept_offline::<_, MockChip, MockHost>(&rel, &c, &dsm);
        assert_eq!(first, Ok(()));
        assert_eq!(second, Ok(()));
    }
}
