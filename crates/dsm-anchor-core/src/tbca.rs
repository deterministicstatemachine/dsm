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

/// The canonical transition-bound counter-advance binding the enrolled anchor ECC
/// key signs, and the same vehicle the receiver's [`crate::root_advance::CounterAdvanceBinding`]
/// hashes to. Covers the full ten-field transition identity:
/// `H(tag ‖ anchor_id ‖ r_R ‖ D ‖ M ‖ R_i ‖ R_{i+1} ‖ hᵢ ‖ hᵢ₊₁ ‖ uᵢ ‖ uᵢ+1)`.
///
/// * `anchor_id`, `receiver_challenge` (`r_R`) — who attested, for which receiver;
/// * `transition_digest` (`D`), `root_advance_message` (`M`) — the transition;
/// * `sender_device_root_before/after` (`R_i`, `R_{i+1}`) — the sender **device** SMT
///   roots that commit the anchor state `(B, Aᵢ, J_b, uᵢ)` / `(B, A_{i+1}, J_{b'}, uᵢ+1)`;
/// * `appliance_root_before/after` (`hᵢ`, `hᵢ₊₁`) — the appliance frontier the release
///   binds that committed state to (distinct from the device roots — never conflated);
/// * `anchor_counter`, `next_anchor_counter` (`uᵢ`, `uᵢ+1`) — the counter coordinate pair.
///
/// The counter movement is the coordinate pair `uᵢ → uᵢ+1`; the receiver's live reads
/// prove the physical position `H = H₀ − u`. Binding both root pairs is load-bearing:
/// a stale or foreign read cannot be spliced into another transition even if it names
/// the same counter position, and a device-root vs appliance-root confusion is impossible.
#[allow(clippy::too_many_arguments)]
pub fn tbca_message(
    anchor_id: &[u8; 32],
    receiver_challenge: &[u8; 32],
    transition_digest: &[u8; 32],
    root_advance_message: &[u8; 32],
    sender_device_root_before: &[u8; 32],
    sender_device_root_after: &[u8; 32],
    appliance_root_before: &[u8; 32],
    appliance_root_after: &[u8; 32],
    anchor_counter: u64,
    next_anchor_counter: u64,
) -> [u8; 32] {
    h(
        domain::TBCA_MESSAGE_V1,
        &[
            anchor_id,
            receiver_challenge,
            transition_digest,
            root_advance_message,
            sender_device_root_before,
            sender_device_root_after,
            appliance_root_before,
            appliance_root_after,
            &u64_le(anchor_counter),
            &u64_le(next_anchor_counter),
        ],
    )
}

/// One enrolled-anchor attestation over a transition-bound counter advance: every
/// field [`tbca_message`] binds except the shared `(anchor_id, uᵢ, uᵢ+1)` (which
/// [`TbcaDoubleAttestation`] carries once). Self-describing so a fraud proof needs
/// no external context.
#[derive(Clone)]
pub struct TbcaAttestation {
    pub receiver_challenge: [u8; 32],
    pub transition_digest: [u8; 32],
    pub root_advance_message: [u8; 32],
    pub sender_device_root_before: [u8; 32],
    pub sender_device_root_after: [u8; 32],
    pub appliance_root_before: [u8; 32],
    pub appliance_root_after: [u8; 32],
    pub sig: Vec<u8>,
}

/// Verify a single TBCA: the counter advanced by exactly one coordinate step and the
/// enrolled anchor signed that movement bound to this exact transition. This is the
/// transition-bound replacement for a bare authenticated scalar counter read.
pub fn verify_tbca<T: TbcaSig>(
    anchor_pk: &[u8],
    anchor_id: &[u8; 32],
    anchor_counter: u64,
    next_anchor_counter: u64,
    att: &TbcaAttestation,
) -> bool {
    // A transfer consumes exactly one counter step: uᵢ → uᵢ+1 (equivalently
    // H_new = H_old − 1, since H = H₀ − u).
    if anchor_counter.checked_add(1) != Some(next_anchor_counter) {
        return false;
    }
    let msg = tbca_message(
        anchor_id,
        &att.receiver_challenge,
        &att.transition_digest,
        &att.root_advance_message,
        &att.sender_device_root_before,
        &att.sender_device_root_after,
        &att.appliance_root_before,
        &att.appliance_root_after,
        anchor_counter,
        next_anchor_counter,
    );
    T::verify(anchor_pk, &msg, &att.sig)
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
    pub anchor_counter: u64,
    pub next_anchor_counter: u64,
    pub a: TbcaAttestation,
    pub b: TbcaAttestation,
}

impl TbcaDoubleAttestation {
    /// Valid iff both TBCAs verify under `anchor_pk`, share the exact same counter
    /// coordinate movement, and name two distinct transitions (`M_a ≠ M_b`). Two valid
    /// attestations of one counter position for two transitions = the fork.
    pub fn verify<T: TbcaSig>(&self, anchor_pk: &[u8]) -> bool {
        // Distinct transitions — else it is the same attestation twice, not a fork.
        if ct_eq_32(&self.a.root_advance_message, &self.b.root_advance_message) {
            return false;
        }
        verify_tbca::<T>(
            anchor_pk,
            &self.anchor_id,
            self.anchor_counter,
            self.next_anchor_counter,
            &self.a,
        ) && verify_tbca::<T>(
            anchor_pk,
            &self.anchor_id,
            self.anchor_counter,
            self.next_anchor_counter,
            &self.b,
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

    /// Build a signed [`TbcaAttestation`] over the ten-field binding (mock sk == pk).
    #[allow(clippy::too_many_arguments)]
    fn att(
        sk: &[u8; 32],
        aid: &[u8; 32],
        uc: u64,
        nuc: u64,
        rc: [u8; 32],
        d: [u8; 32],
        m: [u8; 32],
        rib: [u8; 32],
        ria: [u8; 32],
        hib: [u8; 32],
        hia: [u8; 32],
    ) -> TbcaAttestation {
        let msg = tbca_message(aid, &rc, &d, &m, &rib, &ria, &hib, &hia, uc, nuc);
        TbcaAttestation {
            receiver_challenge: rc,
            transition_digest: d,
            root_advance_message: m,
            sender_device_root_before: rib,
            sender_device_root_after: ria,
            appliance_root_before: hib,
            appliance_root_after: hia,
            sig: mock_sign(sk, &msg),
        }
    }

    #[test]
    fn tbca_roundtrip_and_field_binding() {
        let pk = f(0xAB); // sk == pk for the mock
        let aid = f(1);
        let (uc, nuc) = (0u64, 1u64);
        let a = att(&pk, &aid, uc, nuc, f(5), f(2), f(3), f(6), f(7), f(8), f(9));
        assert!(verify_tbca::<MockTbca>(&pk, &aid, uc, nuc, &a));

        // Every bound field is load-bearing: flipping any one breaks verification. The
        // mock signs the ten-field message, so tampering a field after signing yields a
        // sig over a stale message that no longer recomputes.
        let tamper = |mut t: TbcaAttestation, f: &dyn Fn(&mut TbcaAttestation)| {
            f(&mut t);
            t
        };
        assert!(!verify_tbca::<MockTbca>(&f(0x99), &aid, uc, nuc, &a)); // wrong anchor pk
        assert!(!verify_tbca::<MockTbca>(&pk, &f(0x99), uc, nuc, &a)); // wrong anchor id
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, uc, nuc,
            &tamper(a.clone(), &|t| t.receiver_challenge = f(0x99))));
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, uc, nuc,
            &tamper(a.clone(), &|t| t.transition_digest = f(0x99))));
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, uc, nuc,
            &tamper(a.clone(), &|t| t.root_advance_message = f(0x99))));
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, uc, nuc,
            &tamper(a.clone(), &|t| t.sender_device_root_before = f(0x99))));
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, uc, nuc,
            &tamper(a.clone(), &|t| t.sender_device_root_after = f(0x99))));
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, uc, nuc,
            &tamper(a.clone(), &|t| t.appliance_root_before = f(0x99))));
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, uc, nuc,
            &tamper(a.clone(), &|t| t.appliance_root_after = f(0x99))));
        // Wrong coordinate pair (message binds uᵢ/uᵢ+1) — but keep the unit step so the
        // rejection is the binding, not the arithmetic guard.
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, 5, 6, &a));
    }

    #[test]
    fn tbca_rejects_non_unit_counter_step() {
        let pk = f(0xAB);
        let aid = f(1);
        // next must be exactly counter + 1; a 2-step (or 0-step) claim is rejected even
        // with an otherwise valid signature over the claimed coordinates.
        let a = att(&pk, &aid, 0, 2, f(5), f(2), f(3), f(6), f(7), f(8), f(9));
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, 0, 2, &a));

        // And a wraparound (next == 0) is rejected.
        let a0 = att(&pk, &aid, u64::MAX, 0, f(5), f(2), f(3), f(6), f(7), f(8), f(9));
        assert!(!verify_tbca::<MockTbca>(&pk, &aid, u64::MAX, 0, &a0));
    }

    #[test]
    fn tbca_double_attestation_is_a_valid_fraud_proof() {
        let pk = f(0xAB);
        let aid = f(1);
        let (uc, nuc) = (0u64, 1u64);
        // Same counter coordinate, two distinct successors (different M / roots / r_R).
        let a = att(&pk, &aid, uc, nuc, f(5), f(0x2A), f(0x1A), f(6), f(0x7A), f(8), f(0x9A));
        let b = att(&pk, &aid, uc, nuc, f(6), f(0x2B), f(0x1B), f(6), f(0x7B), f(8), f(0x9B));

        let proof = TbcaDoubleAttestation {
            anchor_id: aid,
            anchor_counter: uc,
            next_anchor_counter: nuc,
            a,
            b,
        };
        assert!(proof.verify::<MockTbca>(&pk));
    }

    #[test]
    fn tbca_double_attestation_rejects_same_transition_and_bad_sig() {
        let pk = f(0xAB);
        let aid = f(1);
        let (uc, nuc) = (0u64, 1u64);
        let a = att(&pk, &aid, uc, nuc, f(5), f(0x2A), f(0x1A), f(6), f(0x7A), f(8), f(0x9A));

        // Same M on both sides is not a fork — reject.
        let same = TbcaDoubleAttestation {
            anchor_id: aid,
            anchor_counter: uc,
            next_anchor_counter: nuc,
            a: a.clone(),
            b: a.clone(),
        };
        assert!(!same.verify::<MockTbca>(&pk));

        // Distinct transitions but one signature is invalid — reject.
        let mut bad_b = att(&pk, &aid, uc, nuc, f(6), f(0x2B), f(0x1B), f(6), f(0x7B), f(8), f(0x9B));
        bad_b.sig = vec![0u8; 32]; // not a valid mock signature
        let bad = TbcaDoubleAttestation {
            anchor_id: aid,
            anchor_counter: uc,
            next_anchor_counter: nuc,
            a,
            b: bad_b,
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
