//! The v2 receiver acceptance predicate (§13, Def. 12) — Software Authority, Hardware
//! Identity. An honest receiver accepts an offline root advance iff every check below
//! holds. Acceptance verifies **software objects only**: the three signatures over
//! `M_{i+1}` (`σ^DSM` seed, `σ^chip` resident-chip, `σ^host` partition), the device-SMT
//! inclusion proofs `Π_i`/`Π_{i+1}`, the forward-only frontier (directly or via a
//! `BranchProof`), the challenge, the recipient and the checked counter increment. **No step
//! reads hardware.** There is no verify-live
//! and no optional audit path: the verifier has no live-hardware dependency — it verifies
//! signed identity evidence (`σ^chip`/`σ^host`) against the public keys enrolled in `B`.
//! Removing the live hardware checks does not remove the chip and host witness requirements
//! (§ Corollary 1).
//!
//! The anchor's identity is pinned on first use (DSM Amendment A24): a receiver pins a
//! holder's bundle `B`, `anchor_id`, `pk_chip` and `pk_host` when the bundle recomputes for the
//! holder's online key, device id and policy, and a later release under any other identity
//! fails step 1, the pin kept. Nothing here can learn of a compromise or revocation of the
//! anchor found elsewhere: an offline receiver checks the evidence it is handed, and the
//! answer to a compromised anchor is the holder's online unload. Delivery to this receiver is
//! the DSM receipt's, which Core checks before the predicate runs.
//!
//! Uniqueness is a software property of the DSM device SMT: one parent root `R_i` admits
//! at most one accepted successor per receiver (the adopted frontier is forward-only, so a
//! later release claiming an already-consumed frontier is rejected on sight). Cross-receiver
//! forks are position collisions exposed by Tripwire on reconciliation, not prevented here.

use crate::root_advance::{
    anchor_root_advance, root_advance_message, transition_digest, Certificate, OfflineRelease,
};
use crate::tropic::{ChipSig, HostSig};
use crate::util::ct_eq_32;

/// The DSM-state verifier the receiver supplies. The device SMT is the software authority;
/// these checks are implemented by the dsm layer (SMT inclusion + DSM transition validity,
/// the latter carrying `σ^DSM`).
pub trait DsmVerifier {
    /// The device SMT `root` commits the offline account of `bundle` with its software
    /// counter at `counter` and its frontier at `frontier`, via `proof`. The account is its
    /// own SMT whose root is one device-SMT leaf; the counter in it is the authority the
    /// hardware counter mirrors. The verifier records why a proof is refused;
    /// the predicate needs only that it was.
    fn verify_offline_state(
        &self,
        root: &[u8; 32],
        bundle: &[u8; 32],
        frontier: &[u8; 32],
        counter: u64,
        proof: &[u8],
    ) -> Result<(), OfflineStateRefused>;
    /// The DSM transition (`σ^DSM` + whole-state consumption `R_i → R_{i+1}`) verifies. The
    /// transition is located by its canonical digest `D` plus the frontier pair so the dsm
    /// layer can check it without re-borrowing the wire `Transition`.
    fn verify_transition(
        &self,
        transition_digest: &[u8; 32],
        prev_root: &[u8; 32],
        next_root: &[u8; 32],
    ) -> bool;
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
}

/// The DSM verifier refused an offline-state proof: the device root does not
/// commit the offline account at the frontier and counter named.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OfflineStateRefused;

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
    /// `Π_{i+1}` does not prove `R_{i+1}` commits `(B, h_{i+1}, u_i+1)`.
    NextStateUncommitted,
    /// Authority policy hash mismatch.
    PolicyMismatch,
    /// A BranchProof hop does not chain / verify.
    BranchProofInvalid,
}

/// Recompute `h_{i+1}` and `M_{i+1}` from a certificate's own carried fields and verify the
/// chip + host signatures over that `M`. Works for the accepted release AND for each
/// `BranchProof` hop — a hop carries its own `transition_digest`, so no `Δ` is needed. Note
/// this does NOT recompute `D` from `Δ°`; that Δ°-binding check is done once, on the accepted
/// release only, in [`accept_offline`].
pub fn verify_cert_frontier_and_sigs<C: ChipSig, P: HostSig>(
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
    if !P::verify(pk_host, &m, &cert.sigma_host) {
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
    P: HostSig,
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

    // (3) Π_i proves R_i commits the offline account of B at (h_i, u_i).
    dsm.verify_offline_state(
        &cert.sender_device_root_before,
        ctx.pinned_bundle,
        &cert.prev_frontier,
        cert.anchor_counter,
        &rel.offline_state_proof_before,
    )
    .map_err(|OfflineStateRefused| AcceptError::PrevStateUncommitted)?;

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

    // (14) Π_{i+1} proves R_{i+1} commits the offline account of B at (h_{i+1}, u_i+1).
    dsm.verify_offline_state(
        &cert.sender_device_root_after,
        ctx.pinned_bundle,
        &cert.next_frontier,
        cert.next_anchor_counter,
        &rel.offline_state_proof_after,
    )
    .map_err(|OfflineStateRefused| AcceptError::NextStateUncommitted)?;

    // (15) Authority policy hash matches the previous state.
    if !ct_eq_32(t.authority_policy_hash, ctx.expected_policy_hash) {
        return Err(AcceptError::PolicyMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use crate::hash::h;
    use crate::root_advance::OwnedTransition;
    use crate::tropic::{PartitionError, PartitionSig};
    use alloc::vec::Vec;

    // --- the real signature schemes: the receiver verifies what the appliance signs ---

    /// The resident chip key, Ed25519 as on the TROPIC01: `σ^chip` verifies only under the
    /// pinned `pk_chip`, and only its holder can sign.
    struct Ed25519Chip;
    impl ChipSig for Ed25519Chip {
        fn verify(pk_chip: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
            use ed25519_dalek::Verifier;
            let key: Result<[u8; 32], _> = pk_chip.try_into();
            let signature: Result<[u8; 64], _> = sig.try_into();
            matches!(
                (key, signature),
                (Ok(key), Ok(signature)) if matches!(
                    ed25519_dalek::VerifyingKey::from_bytes(&key).map(|vk| vk
                        .verify(message, &ed25519_dalek::Signature::from_bytes(&signature))),
                    Ok(Ok(()))
                )
            )
        }
    }
    fn chip_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0x33; 32])
    }
    fn pk_chip() -> &'static [u8] {
        static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
        KEY.get_or_init(|| chip_key().verifying_key().to_bytes())
    }
    fn chip_sign(m: &[u8; 32]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        chip_key().sign(m).to_bytes().to_vec()
    }

    /// The partition key, BLAKE3-SPHINCS+ SPX128f as on the RP2350: `σ^host` verifies only
    /// under the pinned `pk_host`.
    const PARTITION: dsm_sphincs::SphincsVariant = dsm_sphincs::SphincsVariant::SPX128f;
    struct SphincsHost;
    impl PartitionSig for SphincsHost {
        fn part_keygen(seed: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), PartitionError> {
            let kp = dsm_sphincs::generate_keypair_from_seed(PARTITION, seed)
                .map_err(partition_error)?;
            Ok((kp.secret_key.clone(), kp.public_key.clone()))
        }
        fn part_sign(sk: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, PartitionError> {
            dsm_sphincs::sign(PARTITION, sk, digest).map_err(partition_error)
        }
        fn part_verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
            matches!(dsm_sphincs::verify(PARTITION, pk, digest, sig), Ok(valid) if valid)
        }
    }
    /// The SPHINCS+ failure, as the partition reports it.
    fn partition_error(e: dsm_sphincs::Error) -> PartitionError {
        match e {
            dsm_sphincs::Error::Crypto(dsm_sphincs::CryptoFailure::BadSecretKeySize) => {
                PartitionError::SecretKey
            }
            dsm_sphincs::Error::Crypto(
                dsm_sphincs::CryptoFailure::EmptySigningMessage
                | dsm_sphincs::CryptoFailure::EmptyVerificationMessage,
            ) => PartitionError::Message,
            dsm_sphincs::Error::Crypto(dsm_sphincs::CryptoFailure::SignerSelfCheck) => {
                PartitionError::SelfCheck
            }
        }
    }
    fn host_keys() -> &'static (Vec<u8>, Vec<u8>) {
        static KEYS: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| match SphincsHost::part_keygen(&[0x44; 32]) {
            Ok(keys) => keys,
            Err(e) => panic!("the partition key: {e:?}"),
        })
    }
    fn pk_host() -> &'static [u8] {
        &host_keys().1
    }
    fn host_sign(m: &[u8; 32]) -> Vec<u8> {
        match SphincsHost::part_sign(&host_keys().0, m) {
            Ok(sig) => sig,
            Err(e) => panic!("the partition signs: {e:?}"),
        }
    }

    /// Which of the dsm layer's checks the test has it refuse: the predicate's handling of the
    /// SMT and transition answers, which the dsm layer computes and this crate only consumes.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Refuse {
        Nothing,
        OfflineState,
        Transition,
    }
    struct DsmChecks {
        refuse: Refuse,
    }
    impl Default for DsmChecks {
        fn default() -> Self {
            Self {
                refuse: Refuse::Nothing,
            }
        }
    }
    impl DsmVerifier for DsmChecks {
        fn verify_offline_state(
            &self,
            _r: &[u8; 32],
            _b: &[u8; 32],
            _f: &[u8; 32],
            _u: u64,
            _p: &[u8],
        ) -> Result<(), OfflineStateRefused> {
            match self.refuse {
                Refuse::OfflineState => Err(OfflineStateRefused),
                Refuse::Nothing | Refuse::Transition => Ok(()),
            }
        }
        fn verify_transition(&self, _d: &[u8; 32], _p: &[u8; 32], _n: &[u8; 32]) -> bool {
            self.refuse != Refuse::Transition
        }
    }

    const B: [u8; 32] = [0x11; 32];
    const ANCHOR_ID: [u8; 32] = [0x22; 32];
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
            sigma_chip: chip_sign(&m),
            sigma_host: host_sign(&m),
            receiver_challenge: R_CHALLENGE,
            recipient: RECIPIENT,
        };

        OfflineRelease {
            transition: owned,
            offline_state_proof_before: alloc::vec![0xCC],
            offline_state_proof_after: alloc::vec![0xDD],
            cert,
            branch_proof: Vec::new(),
        }
    }

    fn ctx(accepted_frontier: &[u8; 32]) -> VerifierContext<'_> {
        VerifierContext {
            pinned_bundle: &B,
            pinned_anchor_id: &ANCHOR_ID,
            pinned_pk_chip: pk_chip(),
            pinned_pk_host: pk_host(),
            accepted_frontier,
            expected_receiver_challenge: &R_CHALLENGE,
            expected_recipient: &RECIPIENT,
            expected_policy_hash: &POLICY,
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
            accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &ctx(&H0), &DsmChecks::default()),
            Err(AcceptError::MessageMismatch)
        );
    }

    // (2) A fully valid three-signature release is accepted.
    #[test]
    fn accepts_valid_release() {
        let rel = valid_release(H0, 0);
        assert_eq!(
            accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &ctx(&H0), &DsmChecks::default()),
            Ok(())
        );
    }

    // (3) Missing / invalid DSM signature (σ^DSM rides on the DSM transition).
    #[test]
    fn rejects_missing_dsm_signature() {
        let rel = valid_release(H0, 0);
        let dsm = DsmChecks {
            refuse: Refuse::Transition,
        };
        assert_eq!(
            accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &ctx(&H0), &dsm),
            Err(AcceptError::TransitionProofInvalid)
        );
    }

    // (3b) The device SMT does not commit the holder's offline account before the advance.
    #[test]
    fn rejects_an_uncommitted_offline_state() {
        let rel = valid_release(H0, 0);
        let dsm = DsmChecks {
            refuse: Refuse::OfflineState,
        };
        assert_eq!(
            accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &ctx(&H0), &dsm),
            Err(AcceptError::PrevStateUncommitted)
        );
    }

    // (4a) A chip signature by any key but the pinned chip's is refused: a signature a holder
    // of only the public key could make does not verify.
    #[test]
    fn rejects_a_chip_signature_by_another_key() {
        use ed25519_dalek::Signer;
        let mut rel = valid_release(H0, 0);
        let other = ed25519_dalek::SigningKey::from_bytes(&[0x34; 32]);
        rel.cert.sigma_chip = other
            .sign(&rel.cert.root_advance_message)
            .to_bytes()
            .to_vec();
        assert_eq!(
            accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &ctx(&H0), &DsmChecks::default()),
            Err(AcceptError::ChipSigInvalid)
        );
    }

    // (4) Missing / invalid chip signature.
    #[test]
    fn rejects_missing_chip_signature() {
        let mut rel = valid_release(H0, 0);
        rel.cert.sigma_chip.clear();
        assert_eq!(
            accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &ctx(&H0), &DsmChecks::default()),
            Err(AcceptError::ChipSigInvalid)
        );
    }

    // (5) Missing / invalid host signature.
    #[test]
    fn rejects_missing_host_signature() {
        let mut rel = valid_release(H0, 0);
        rel.cert.sigma_host.clear();
        assert_eq!(
            accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &ctx(&H0), &DsmChecks::default()),
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
            accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &c, &DsmChecks::default()),
            Err(AcceptError::ChipSigInvalid)
        );

        let mut c = ctx(&H0);
        c.pinned_pk_host = &wrong;
        assert_eq!(
            accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &c, &DsmChecks::default()),
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
        rel.cert.sigma_chip = chip_sign(&m);
        rel.cert.sigma_host = host_sign(&m);
        assert_eq!(
            accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &ctx(&H0), &DsmChecks::default()),
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
            accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &c, &DsmChecks::default()),
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
            accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &c, &DsmChecks::default()),
            Err(AcceptError::RecipientMismatch)
        );
    }

    // (10) Stale frontier with no BranchProof is rejected.
    #[test]
    fn rejects_stale_frontier_without_branch_proof() {
        let rel = valid_release(H0, 0);
        let already_consumed = [0xF0; 32];
        assert_eq!(
            accept_offline::<_, Ed25519Chip, SphincsHost>(
                &rel,
                &ctx(&already_consumed),
                &DsmChecks::default()
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
            sigma_chip: chip_sign(&m_hop),
            sigma_host: host_sign(&m_hop),
            receiver_challenge: R_CHALLENGE,
            recipient: RECIPIENT,
        };

        let mut rel = valid_release(h_bridge, 1); // current advance starts at the bridged frontier
        rel.branch_proof = alloc::vec![hop];
        assert_eq!(
            accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &ctx(&old), &DsmChecks::default()),
            Ok(())
        );
    }

    // (12) Replay idempotence: the predicate is pure — accepting the same release twice yields
    // the same verdict and mutates nothing.
    #[test]
    fn replay_idempotence() {
        let rel = valid_release(H0, 0);
        let c = ctx(&H0);
        let dsm = DsmChecks::default();
        let first = accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &c, &dsm);
        let second = accept_offline::<_, Ed25519Chip, SphincsHost>(&rel, &c, &dsm);
        assert_eq!(first, Ok(()));
        assert_eq!(second, Ok(()));
    }
}
