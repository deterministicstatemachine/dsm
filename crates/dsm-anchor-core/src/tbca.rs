//! Transition-Bound Counter Attestation (TBCA) and offline-bearer fraud proofs.
//!
//! # Honest scope — read before extending
//!
//! TBCA does **not** prevent an offline double-spend under a breached RP2350
//! secure partition, and no TROPIC01 primitive can. The chip's one-time output
//! (`MAC_And_Destroy`) is *symmetric* (not receiver-verifiable); its verifiable
//! (ECC) signer is *repeatable*; and there is no counter-gated signature
//! composing `MCounter` with a signer. So a breached partition can emit two
//! TBCAs at one counter position — decrement once, ECC-sign twice — exactly the
//! "one decrement, two releases" fork. Prevention stays conditioned on the
//! partition key: while it is secret (clones, honest devices, malicious hosts)
//! the one-cert-per-step partition state machine *is* the counter-gated signer
//! and no fork is producible; under partition breach the guarantee degrades to
//! detection. This is the paper's Theorem A/B boundary.
//!
//! What TBCA buys over the bare scalar counter read the predicate accepts today
//! (`accept.rs` checks 17–19 read a live `H` and check `H == H0 − (uᵢ+1)`, with
//! the transcript otherwise unbound):
//!
//! 1. **Counter evidence becomes transition-bound.** TBCA requires the enrolled
//!    anchor to sign a statement naming the counter movement `H_old → H_new`
//!    *and* the exact transition (`M`, `hᵢ`, `hᵢ₊₁`, `r_R`). A stolen or replayed
//!    scalar read is no longer counter-evidence for a transfer.
//! 2. **Detection + attribution.** Two TBCAs naming the same `(anchor_id, H_old,
//!    H_new)` for two distinct transitions are a self-contained, chip-signed,
//!    offline-verifiable proof that the enrolled anchor attested two successors
//!    at one counter position — a portable double-spend proof attributable to the
//!    device lineage, sharper than a Tripwire tip conflict.
//!
//! The witness-side analogue — two WOTS witness signatures under one one-time
//! `pk_hw` over distinct digests — is [`WitnessDoubleOpen`].

extern crate alloc;
use alloc::vec::Vec;

use crate::domain;
use crate::hash::h;
use crate::tropic::WitnessSig;
use crate::util::{ct_eq_32, u64_le};

/// The enrolled-anchor ECC signature scheme (TROPIC01 `EdDSA`/`ECDSA` over the
/// anchor's own persistent key). Distinct from [`crate::tropic::PartitionSig`]
/// (the RP2350 partition key) and [`WitnessSig`] (the per-step MACANDD-seeded WOTS
/// key): this is the chip's persistent asymmetric identity key, whose public half
/// is enrolled with the anchor and pinned by the receiver. Injected as a trait so
/// the core stays hardware- and curve-agnostic; the SDK wires the real verify.
pub trait TbcaSig {
    /// Verify a TBCA signature over a 32-byte message under the enrolled anchor pk.
    fn verify(anchor_pk: &[u8], msg: &[u8; 32], sig: &[u8]) -> bool;
}

/// The TBCA message the enrolled anchor ECC key signs:
/// `H(tag ‖ anchor_id ‖ H_old ‖ H_new ‖ M ‖ hᵢ ‖ hᵢ₊₁ ‖ r_R)`.
///
/// `H_old`/`H_new` are the live TROPIC down-counter values before/after the step
/// (`H_new = H_old − 1`); `M` is the root-advance message (which already binds the
/// full transition — recipient, object, roots, counters, policy, challenge); the
/// roots and `r_R` are named explicitly so the attestation is self-describing and
/// a fraud proof needs no external context to check.
pub fn tbca_message(
    anchor_id: &[u8; 32],
    h_old: u64,
    h_new: u64,
    m: &[u8; 32],
    prev_root: &[u8; 32],
    next_root: &[u8; 32],
    receiver_challenge: &[u8; 32],
) -> [u8; 32] {
    h(
        domain::TBCA_MESSAGE_V1,
        &[
            anchor_id,
            &u64_le(h_old),
            &u64_le(h_new),
            m,
            prev_root,
            next_root,
            receiver_challenge,
        ],
    )
}

/// Verify a single TBCA: the counter moved by exactly one step and the enrolled
/// anchor signed that movement bound to this exact transition. This is the
/// transition-bound replacement for a bare authenticated scalar counter read.
#[allow(clippy::too_many_arguments)]
pub fn verify_tbca<T: TbcaSig>(
    anchor_pk: &[u8],
    anchor_id: &[u8; 32],
    h_old: u64,
    h_new: u64,
    m: &[u8; 32],
    prev_root: &[u8; 32],
    next_root: &[u8; 32],
    receiver_challenge: &[u8; 32],
    sig: &[u8],
) -> bool {
    // A transfer consumes exactly one counter step: H_new = H_old − 1
    // (equivalently uᵢ → uᵢ+1, since H = H₀ − u).
    if h_old.checked_sub(1) != Some(h_new) {
        return false;
    }
    let msg = tbca_message(
        anchor_id,
        h_old,
        h_new,
        m,
        prev_root,
        next_root,
        receiver_challenge,
    );
    T::verify(anchor_pk, &msg, sig)
}

/// A TBCA double-attestation fraud proof: the enrolled anchor signed two TBCAs
/// naming the **same** counter movement `(anchor_id, H_old, H_new)` for two
/// **distinct** transitions. Under partition breach this is producible (decrement
/// once, ECC-sign twice) and therefore not preventable — but it is a
/// self-contained, chip-signed, offline-verifiable proof of an offline
/// double-spend, attributable to the enrolled anchor. Each side carries the
/// transition-identifying fields it was signed over.
pub struct TbcaDoubleAttestation {
    pub anchor_id: [u8; 32],
    pub h_old: u64,
    pub h_new: u64,
    pub m_a: [u8; 32],
    pub prev_root_a: [u8; 32],
    pub next_root_a: [u8; 32],
    pub receiver_challenge_a: [u8; 32],
    pub sig_a: Vec<u8>,
    pub m_b: [u8; 32],
    pub prev_root_b: [u8; 32],
    pub next_root_b: [u8; 32],
    pub receiver_challenge_b: [u8; 32],
    pub sig_b: Vec<u8>,
}

impl TbcaDoubleAttestation {
    /// Valid iff both TBCAs verify under `anchor_pk`, share the exact same counter
    /// movement, and name two distinct transitions (`M_a ≠ M_b`). Two valid
    /// attestations of one counter position for two transitions = the fork.
    pub fn verify<T: TbcaSig>(&self, anchor_pk: &[u8]) -> bool {
        // Distinct transitions — else it is the same attestation twice, not a fork.
        if ct_eq_32(&self.m_a, &self.m_b) {
            return false;
        }
        verify_tbca::<T>(
            anchor_pk,
            &self.anchor_id,
            self.h_old,
            self.h_new,
            &self.m_a,
            &self.prev_root_a,
            &self.next_root_a,
            &self.receiver_challenge_a,
            &self.sig_a,
        ) && verify_tbca::<T>(
            anchor_pk,
            &self.anchor_id,
            self.h_old,
            self.h_new,
            &self.m_b,
            &self.prev_root_b,
            &self.next_root_b,
            &self.receiver_challenge_b,
            &self.sig_b,
        )
    }
}

/// A witness-key double-open fraud proof: two WOTS witness signatures that both
/// verify under the **same** one-time public key `pk_hw` over two **distinct**
/// digests. A WOTS key is one-time by construction, so two valid openings prove
/// the enrolled per-step witness authority signed two different transition
/// messages — the witness-side analogue of [`TbcaDoubleAttestation`].
pub struct WitnessDoubleOpen {
    pub pk_hw: Vec<u8>,
    pub digest_a: [u8; 32],
    pub sig_a: Vec<u8>,
    pub digest_b: [u8; 32],
    pub sig_b: Vec<u8>,
}

impl WitnessDoubleOpen {
    /// Valid iff both signatures verify under `pk_hw` over two distinct digests.
    pub fn verify<S: WitnessSig>(&self) -> bool {
        !ct_eq_32(&self.digest_a, &self.digest_b)
            && S::verify(&self.pk_hw, &self.digest_a, &self.sig_a)
            && S::verify(&self.pk_hw, &self.digest_b, &self.sig_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::WotsBlake3;

    /// Test-only symmetric TBCA scheme: `pk == sk`, `sig = H("mock" ‖ pk ‖ msg)`.
    /// The real anchor scheme is asymmetric ECC injected by the SDK; this mock
    /// exercises the TBCA binding/encoding and fraud-proof logic, not the curve.
    struct MockTbca;
    const MOCK_TAG: &str = "DSM/test/mock-tbca/v1";

    fn mock_sign(sk: &[u8; 32], msg: &[u8; 32]) -> Vec<u8> {
        h(MOCK_TAG, &[sk, msg]).to_vec()
    }

    impl TbcaSig for MockTbca {
        fn verify(anchor_pk: &[u8], msg: &[u8; 32], sig: &[u8]) -> bool {
            anchor_pk.len() == 32 && sig == h(MOCK_TAG, &[anchor_pk, msg]).as_slice()
        }
    }

    fn f(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn tbca_roundtrip_and_field_binding() {
        let pk = f(0xAB); // sk == pk for the mock
        let (aid, m, pr, nr, rc) = (f(1), f(2), f(3), f(4), f(5));
        let (h_old, h_new) = (1000u64, 999u64);
        let msg = tbca_message(&aid, h_old, h_new, &m, &pr, &nr, &rc);
        let sig = mock_sign(&pk, &msg);

        assert!(verify_tbca::<MockTbca>(
            &pk, &aid, h_old, h_new, &m, &pr, &nr, &rc, &sig
        ));

        // Every bound field is load-bearing: flipping any one breaks verification.
        assert!(!verify_tbca::<MockTbca>(&pk, &f(9), h_old, h_new, &m, &pr, &nr, &rc, &sig));
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, h_old, h_new, &f(9), &pr, &nr, &rc, &sig));
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, h_old, h_new, &m, &f(9), &nr, &rc, &sig));
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, h_old, h_new, &m, &pr, &f(9), &rc, &sig));
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, h_old, h_new, &m, &pr, &nr, &f(9), &sig));
        // Wrong anchor key.
        assert!(!verify_tbca::<MockTbca>(&f(0xCD), &aid, h_old, h_new, &m, &pr, &nr, &rc, &sig));
    }

    #[test]
    fn tbca_rejects_non_unit_counter_step() {
        let pk = f(0xAB);
        let (aid, m, pr, nr, rc) = (f(1), f(2), f(3), f(4), f(5));
        // H_new must be exactly H_old − 1; a 2-step (or 0-step) claim is rejected
        // even with an otherwise valid signature over the claimed values.
        let (h_old, h_new) = (1000u64, 998u64);
        let msg = tbca_message(&aid, h_old, h_new, &m, &pr, &nr, &rc);
        let sig = mock_sign(&pk, &msg);
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, h_old, h_new, &m, &pr, &nr, &rc, &sig));

        // And H_old == 0 (would underflow) is rejected.
        let msg0 = tbca_message(&aid, 0, 0, &m, &pr, &nr, &rc);
        let sig0 = mock_sign(&pk, &msg0);
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, 0, 0, &m, &pr, &nr, &rc, &sig0));
    }

    #[test]
    fn tbca_double_attestation_is_a_valid_fraud_proof() {
        let pk = f(0xAB);
        let (aid, rc_a, rc_b) = (f(1), f(5), f(6));
        let (h_old, h_new) = (1000u64, 999u64);
        // Same counter movement, two distinct successors (different M and next_root).
        let (m_a, pr, nr_a) = (f(0x1A), f(3), f(0x4A));
        let (m_b, nr_b) = (f(0x1B), f(0x4B));
        let sig_a = mock_sign(&pk, &tbca_message(&aid, h_old, h_new, &m_a, &pr, &nr_a, &rc_a));
        let sig_b = mock_sign(&pk, &tbca_message(&aid, h_old, h_new, &m_b, &pr, &nr_b, &rc_b));

        let proof = TbcaDoubleAttestation {
            anchor_id: aid,
            h_old,
            h_new,
            m_a,
            prev_root_a: pr,
            next_root_a: nr_a,
            receiver_challenge_a: rc_a,
            sig_a,
            m_b,
            prev_root_b: pr,
            next_root_b: nr_b,
            receiver_challenge_b: rc_b,
            sig_b,
        };
        assert!(proof.verify::<MockTbca>(&pk));
    }

    #[test]
    fn tbca_double_attestation_rejects_same_transition_and_bad_sig() {
        let pk = f(0xAB);
        let (aid, rc) = (f(1), f(5));
        let (h_old, h_new) = (1000u64, 999u64);
        let (m, pr, nr) = (f(0x1A), f(3), f(0x4A));
        let sig = mock_sign(&pk, &tbca_message(&aid, h_old, h_new, &m, &pr, &nr, &rc));

        // Same M on both sides is not a fork — reject.
        let same = TbcaDoubleAttestation {
            anchor_id: aid,
            h_old,
            h_new,
            m_a: m,
            prev_root_a: pr,
            next_root_a: nr,
            receiver_challenge_a: rc,
            sig_a: sig.clone(),
            m_b: m,
            prev_root_b: pr,
            next_root_b: nr,
            receiver_challenge_b: rc,
            sig_b: sig.clone(),
        };
        assert!(!same.verify::<MockTbca>(&pk));

        // Distinct transitions but one signature is invalid — reject.
        let m_b = f(0x1B);
        let bad = TbcaDoubleAttestation {
            anchor_id: aid,
            h_old,
            h_new,
            m_a: m,
            prev_root_a: pr,
            next_root_a: nr,
            receiver_challenge_a: rc,
            sig_a: sig,
            m_b,
            prev_root_b: pr,
            next_root_b: f(0x4B),
            receiver_challenge_b: rc,
            sig_b: vec![0u8; 32], // not a valid mock signature
        };
        assert!(!bad.verify::<MockTbca>(&pk));
    }

    #[test]
    fn witness_double_open_is_a_valid_fraud_proof() {
        let seed = [7u8; 32];
        let (sk, pk_hw) = WotsBlake3::keygen(&seed);
        let d_a = h("test/m-t", &[b"transition-A"]);
        let d_b = h("test/m-t", &[b"transition-B"]);
        let sig_a = WotsBlake3::sign(&sk, &d_a);
        let sig_b = WotsBlake3::sign(&sk, &d_b);

        let proof = WitnessDoubleOpen {
            pk_hw: pk_hw.clone(),
            digest_a: d_a,
            sig_a,
            digest_b: d_b,
            sig_b,
        };
        assert!(proof.verify::<WotsBlake3>());
    }

    #[test]
    fn witness_double_open_rejects_same_digest_and_wrong_key() {
        let seed = [7u8; 32];
        let (sk, pk_hw) = WotsBlake3::keygen(&seed);
        let d = h("test/m-t", &[b"one-transition"]);
        let sig = WotsBlake3::sign(&sk, &d);

        // Same digest twice is one opening, not a double-open.
        let same = WitnessDoubleOpen {
            pk_hw: pk_hw.clone(),
            digest_a: d,
            sig_a: sig.clone(),
            digest_b: d,
            sig_b: sig.clone(),
        };
        assert!(!same.verify::<WotsBlake3>());

        // A signature under a different key does not open this pk_hw.
        let (sk2, _) = WotsBlake3::keygen(&[8u8; 32]);
        let d_b = h("test/m-t", &[b"other"]);
        let wrong = WitnessDoubleOpen {
            pk_hw,
            digest_a: d,
            sig_a: sig,
            digest_b: d_b,
            sig_b: WotsBlake3::sign(&sk2, &d_b),
        };
        assert!(!wrong.verify::<WotsBlake3>());
    }
}
