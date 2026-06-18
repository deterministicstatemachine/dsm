// SPDX-License-Identifier: MIT OR Apache-2.0

//! Device bound signing anchor.
//!
//! A per device hidden state, born inside a secure element and never leaving
//! it, that signs each transition with a post quantum key derived from that
//! state. This replaces fingerprint based anti cloning, which bound on
//! software readable physical channels that a root level adversary can forge
//! or that an honest application cannot measure. The anchor binds instead on
//! a non extractable secret element root, which a copy on other silicon does
//! not hold.
//!
//! # What is secret and what is public
//!
//! The internal root, the walk output, the commitment randomness, and the
//! derived state never leave the element. The published identity is the
//! commitment, the SPHINCS+ public key, the element KEM public key, and the
//! anchor identifier derived from them. A clone gets the public record and
//! still cannot sign, because signing needs the derived state, which needs
//! the internal root.
//!
//! # Birth, single element
//!
//! 1. The element holds an internal root that never leaves.
//! 2. It derives its ML-KEM keypair from that root.
//! 3. It runs a BLAKE3 walk seeded by the root, then commits to the walk
//!    output with a salted BLAKE3 commitment. The commitment is published.
//! 4. The host delivers its contribution by encapsulating to the element KEM
//!    public key. The element decapsulates. The host never learns the root.
//! 5. The element derives the hidden state with HKDF over the root, the host
//!    contribution, and the commitment, then derives a SPHINCS+ key from it.
//! 6. The working values are wiped. Only the hidden state and the signing key
//!    remain inside.
//!
//! # Birth, cross driven pair
//!
//! Two elements privately drive each other. Each generates a drive
//! contribution from its own root and seals it to the peer KEM public key.
//! The host relays the sealed ciphertexts and never sees a drive value. Each
//! anchor is then partly self born and partly peer driven, and a transition
//! requires both signatures over the same challenge. There is no point where
//! the two internal roots meet, so there is no combiner.
//!
//! # Primitives
//!
//! BLAKE3 for hashing, walk, and commitment; ML-KEM-768 for delivery and
//! sealing; HKDF over BLAKE3 for the state derivation; SPHINCS+ (SPX256s,
//! the production default) for signatures. No classical primitive is load
//! bearing: the only value the KEM carries is the host contribution, and the
//! internal root that hides the state is never transmitted.

use crate::crypto::blake3::domain_hash_bytes;
use crate::crypto::hkdf::extract_and_expand;
use crate::crypto::kyber::{
    generate_kyber_keypair_from_entropy, kyber_decapsulate, kyber_encapsulate_deterministic,
};
use crate::crypto::sphincs::{self, SphincsVariant};
use crate::types::error::DsmError;

/// Signature variant for the anchor. SPX256s is the production default in the
/// DSM SPHINCS+ module and takes a uniform 32 byte seed, so deriving the key
/// from a uniform hidden state needs no structured key generation step.
pub const ANCHOR_SPHINCS_VARIANT: SphincsVariant = SphincsVariant::SPX256s;

/// Number of BLAKE3 steps in the internal walk.
const WALK_STEPS: usize = 64;

/// The public record of an anchor. Everything here can be shared. None of it
/// lets a holder sign.
#[derive(Clone, Debug)]
pub struct AnchorIdentity {
    /// Anchor identifier, derived from the commitment and the signing key.
    pub id_anchor: [u8; 32],
    /// SPHINCS+ public key used to verify this anchor's signatures.
    pub sphincs_pk: Vec<u8>,
    /// Element ML-KEM public key, the address the host and peers seal to.
    pub kem_pk: Vec<u8>,
    /// Birth commitment to the internal walk output.
    pub commitment_c: [u8; 32],
}

/// A live anchor. Holds the secrets that, in hardware, never leave the
/// element. The secrets are wiped on drop.
pub struct DeviceAnchor {
    sigma: [u8; 32],
    sphincs_sk: Vec<u8>,
    identity: AnchorIdentity,
}

impl Drop for DeviceAnchor {
    fn drop(&mut self) {
        self.sigma.iter_mut().for_each(|b| *b = 0);
        self.sphincs_sk.iter_mut().for_each(|b| *b = 0);
    }
}

impl DeviceAnchor {
    /// The public record for this anchor.
    pub fn identity(&self) -> &AnchorIdentity {
        &self.identity
    }

    /// Sign a transition. The signed value is the transition challenge, which
    /// is fresh per transition, so a past signature does not help forge a new
    /// one.
    pub fn sign_transition(
        &self,
        h_n: &[u8; 32],
        payload_hash: &[u8; 32],
        policy_id: &[u8],
    ) -> Result<Vec<u8>, DsmError> {
        let challenge = transition_challenge(h_n, payload_hash, policy_id);
        sphincs::sign(ANCHOR_SPHINCS_VARIANT, &self.sphincs_sk, &challenge)
    }
}

/// A cross driven pair of anchors that privately drove each other at birth. A
/// transition under this set requires both signatures.
pub struct AnchorSet {
    pub anchor_a: DeviceAnchor,
    pub anchor_b: DeviceAnchor,
}

/// Internal element state produced at the start of birth. Held only inside the
/// element.
struct ElementSecrets {
    r: [u8; 32],
    kem_pk: Vec<u8>,
    kem_sk: Vec<u8>,
    c: [u8; 32],
}

/// The transition challenge bound by a signature.
pub fn transition_challenge(h_n: &[u8; 32], payload_hash: &[u8; 32], policy_id: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(64 + policy_id.len());
    buf.extend_from_slice(h_n);
    buf.extend_from_slice(payload_hash);
    buf.extend_from_slice(policy_id);
    domain_hash_bytes("DSM/offline-bearer/challenge", &buf)
}

/// Verify a single anchor signature against its published identity.
pub fn verify_transition(
    identity: &AnchorIdentity,
    h_n: &[u8; 32],
    payload_hash: &[u8; 32],
    policy_id: &[u8],
    sig: &[u8],
) -> Result<bool, DsmError> {
    let challenge = transition_challenge(h_n, payload_hash, policy_id);
    sphincs::verify(
        ANCHOR_SPHINCS_VARIANT,
        &identity.sphincs_pk,
        &challenge,
        sig,
    )
}

/// Identifier for a cross driven anchor set.
pub fn id_anchor_set(a: &AnchorIdentity, b: &AnchorIdentity) -> [u8; 32] {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&a.id_anchor);
    buf.extend_from_slice(&b.id_anchor);
    domain_hash_bytes("DSM/anchor/id-set", &buf)
}

/// Sign a transition under a cross driven set. Both elements sign the same
/// challenge.
pub fn sign_transition_set(
    set: &AnchorSet,
    h_n: &[u8; 32],
    payload_hash: &[u8; 32],
    policy_id: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let s_a = set.anchor_a.sign_transition(h_n, payload_hash, policy_id)?;
    let s_b = set.anchor_b.sign_transition(h_n, payload_hash, policy_id)?;
    Ok((s_a, s_b))
}

/// Verify a transition under a cross driven set. Both signatures must verify.
pub fn verify_transition_set(
    a: &AnchorIdentity,
    b: &AnchorIdentity,
    h_n: &[u8; 32],
    payload_hash: &[u8; 32],
    policy_id: &[u8],
    s_a: &[u8],
    s_b: &[u8],
) -> Result<bool, DsmError> {
    let ok_a = verify_transition(a, h_n, payload_hash, policy_id, s_a)?;
    let ok_b = verify_transition(b, h_n, payload_hash, policy_id, s_b)?;
    Ok(ok_a && ok_b)
}

/// The internal walk: a BLAKE3 chain seeded by the internal root. Runs inside
/// the element on a seed that never leaves.
fn walk(r: &[u8; 32]) -> [u8; 32] {
    let mut state = domain_hash_bytes("DSM/anchor/walk-init", r);
    for i in 0..WALK_STEPS {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(&state);
        buf[32..].copy_from_slice(&(i as u64).to_le_bytes());
        state = domain_hash_bytes("DSM/anchor/walk-step", &buf);
    }
    state
}

/// Start of birth for one element: derive the KEM keypair from the internal
/// root, run the walk, and commit to the walk output.
fn element_init(r: &[u8; 32]) -> Result<ElementSecrets, DsmError> {
    let (kem_pk, kem_sk) = generate_kyber_keypair_from_entropy(r, "DSM/anchor/element-kem")?;
    let w = walk(r);
    let r_commit = domain_hash_bytes("DSM/anchor/commit-rand", r);
    let mut cbuf = [0u8; 64];
    cbuf[..32].copy_from_slice(&w);
    cbuf[32..].copy_from_slice(&r_commit);
    let c = domain_hash_bytes("DSM/anchor/commit", &cbuf);
    Ok(ElementSecrets {
        r: *r,
        kem_pk,
        kem_sk,
        c,
    })
}

/// Derive the SPHINCS+ key from the hidden state and assemble the identity.
fn anchor_from_sigma(sigma: [u8; 32], e: &ElementSecrets) -> Result<DeviceAnchor, DsmError> {
    let seed = domain_hash_bytes("DSM/anchor/sphincs-seed", &sigma);
    let kp = sphincs::generate_keypair_from_seed(ANCHOR_SPHINCS_VARIANT, &seed)?;
    let mut idbuf = Vec::with_capacity(32 + kp.public_key.len());
    idbuf.extend_from_slice(&e.c);
    idbuf.extend_from_slice(&kp.public_key);
    let id_anchor = domain_hash_bytes("DSM/anchor/id", &idbuf);
    Ok(DeviceAnchor {
        sigma,
        sphincs_sk: kp.secret_key.clone(),
        identity: AnchorIdentity {
            id_anchor,
            sphincs_pk: kp.public_key.clone(),
            kem_pk: e.kem_pk.clone(),
            commitment_c: e.c,
        },
    })
}

/// Birth a single element anchor.
///
/// `host_seed` is the host's deterministic encapsulation nonce; in deployment
/// the host uses fresh randomness, here it is an explicit input so births are
/// reproducible for testing and known answer checks.
pub fn birth_single(
    r_se: &[u8; 32],
    device_context: &[u8],
    host_seed: &[u8; 32],
) -> Result<DeviceAnchor, DsmError> {
    let e = element_init(r_se)?;

    // Host delivers its contribution by encapsulating to the element KEM key.
    let (k_user, ct_user) = kyber_encapsulate_deterministic(&e.kem_pk, host_seed)?;
    // Element decapsulates; confirm the round trip.
    let k_user_elem = kyber_decapsulate(&e.kem_sk, &ct_user)?;
    if k_user_elem != k_user {
        return Err(DsmError::crypto(
            "anchor birth: KEM round trip mismatch",
            None::<std::io::Error>,
        ));
    }

    // sigma = HKDF(salt, r_se || k_user || C, info = device_context).
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(r_se);
    ikm.extend_from_slice(&k_user);
    ikm.extend_from_slice(&e.c);
    let sigma_v = extract_and_expand(b"DSM/anchor/sigma\0", &ikm, device_context, 32);
    let mut sigma = [0u8; 32];
    sigma.copy_from_slice(&sigma_v);

    anchor_from_sigma(sigma, &e)
}

/// A drive contribution, generated inside the sending element from its own
/// root. This is the value that must never be produced by the host.
fn drive(r: &[u8; 32], tag: &str, peer_pre_id: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(64 + transcript.len());
    ikm.extend_from_slice(r);
    ikm.extend_from_slice(peer_pre_id);
    ikm.extend_from_slice(transcript);
    domain_hash_bytes(tag, &ikm)
}

/// Seal a 32 byte drive value to a peer KEM public key. Returns the KEM
/// ciphertext and the sealed bytes. The host relays both and learns neither
/// the shared secret nor the drive value.
fn seal_to_peer(
    peer_kem_pk: &[u8],
    drive_value: &[u8; 32],
    seal_seed: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), DsmError> {
    let (ss, ct_kem) = kyber_encapsulate_deterministic(peer_kem_pk, seal_seed)?;
    let ks = extract_and_expand(b"DSM/anchor/seal\0", &ss, b"", 32);
    let mut sealed = [0u8; 32];
    for i in 0..32 {
        sealed[i] = drive_value[i] ^ ks[i];
    }
    Ok((ct_kem, sealed))
}

/// Open a sealed drive value with the receiving element KEM secret key.
fn open_from_peer(
    my_kem_sk: &[u8],
    ct_kem: &[u8],
    sealed: &[u8; 32],
) -> Result<[u8; 32], DsmError> {
    let ss = kyber_decapsulate(my_kem_sk, ct_kem)?;
    let ks = extract_and_expand(b"DSM/anchor/seal\0", &ss, b"", 32);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = sealed[i] ^ ks[i];
    }
    Ok(out)
}

/// Finalize one anchor of a cross driven pair: mix the internal root, the host
/// contribution, the peer drive received, the commitment, and the transcript.
fn finalize_cross(
    salt: &[u8],
    e: &ElementSecrets,
    k_user: &[u8],
    peer_drive: &[u8; 32],
    transcript: &[u8],
    device_context: &[u8],
) -> Result<DeviceAnchor, DsmError> {
    let mut ikm = Vec::with_capacity(128 + transcript.len());
    ikm.extend_from_slice(&e.r);
    ikm.extend_from_slice(k_user);
    ikm.extend_from_slice(peer_drive);
    ikm.extend_from_slice(&e.c);
    ikm.extend_from_slice(transcript);
    let sigma_v = extract_and_expand(salt, &ikm, device_context, 32);
    let mut sigma = [0u8; 32];
    sigma.copy_from_slice(&sigma_v);
    anchor_from_sigma(sigma, e)
}

/// Birth a cross driven pair of anchors. Each element drives the other through
/// a sealed channel the host only relays. The `host_seed_*` and `seal_seed_*`
/// inputs are deterministic nonces, explicit so the pair is reproducible.
#[allow(clippy::too_many_arguments)]
pub fn birth_pair(
    r_a: &[u8; 32],
    r_b: &[u8; 32],
    device_context: &[u8],
    transcript: &[u8],
    host_seed_a: &[u8; 32],
    host_seed_b: &[u8; 32],
    seal_seed_ab: &[u8; 32],
    seal_seed_ba: &[u8; 32],
) -> Result<AnchorSet, DsmError> {
    let ea = element_init(r_a)?;
    let eb = element_init(r_b)?;

    // Pre identities used only to bind the drive context to the peer. Derived
    // from the KEM public keys, which are public, so no circular dependency on
    // the not yet derived anchor identity.
    let pre_a = domain_hash_bytes("DSM/anchor/pre-id", &ea.kem_pk);
    let pre_b = domain_hash_bytes("DSM/anchor/pre-id", &eb.kem_pk);

    // Each element generates its drive contribution internally and seals it to
    // the peer. The host relays the sealed ciphertexts.
    let d_a_to_b = drive(r_a, "DSM/anchor/drive-a-to-b", &pre_b, transcript);
    let d_b_to_a = drive(r_b, "DSM/anchor/drive-b-to-a", &pre_a, transcript);
    let (ct_ab, sealed_ab) = seal_to_peer(&eb.kem_pk, &d_a_to_b, seal_seed_ab)?;
    let (ct_ba, sealed_ba) = seal_to_peer(&ea.kem_pk, &d_b_to_a, seal_seed_ba)?;

    // Each element opens what the peer sealed to it.
    let d_b_to_a_at_a = open_from_peer(&ea.kem_sk, &ct_ba, &sealed_ba)?;
    let d_a_to_b_at_b = open_from_peer(&eb.kem_sk, &ct_ab, &sealed_ab)?;

    // Host contributions, one per element.
    let (k_user_a, ct_a) = kyber_encapsulate_deterministic(&ea.kem_pk, host_seed_a)?;
    let k_user_a_elem = kyber_decapsulate(&ea.kem_sk, &ct_a)?;
    let (k_user_b, ct_b) = kyber_encapsulate_deterministic(&eb.kem_pk, host_seed_b)?;
    let k_user_b_elem = kyber_decapsulate(&eb.kem_sk, &ct_b)?;
    if k_user_a_elem != k_user_a || k_user_b_elem != k_user_b {
        return Err(DsmError::crypto(
            "anchor pair birth: KEM round trip mismatch",
            None::<std::io::Error>,
        ));
    }

    let anchor_a = finalize_cross(
        b"DSM/anchor/sigma-a\0",
        &ea,
        &k_user_a,
        &d_b_to_a_at_a,
        transcript,
        device_context,
    )?;
    let anchor_b = finalize_cross(
        b"DSM/anchor/sigma-b\0",
        &eb,
        &k_user_b,
        &d_a_to_b_at_b,
        transcript,
        device_context,
    )?;

    Ok(AnchorSet { anchor_a, anchor_b })
}

// ================================= Tests ====================================

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> &'static [u8] {
        b"device-context/test"
    }

    #[test]
    fn birth_is_deterministic() {
        let r = [0x11u8; 32];
        let host = [0x22u8; 32];
        let a1 = birth_single(&r, ctx(), &host).expect("birth");
        let a2 = birth_single(&r, ctx(), &host).expect("birth");
        assert_eq!(a1.identity().id_anchor, a2.identity().id_anchor);
        assert_eq!(a1.identity().sphincs_pk, a2.identity().sphincs_pk);
        assert_eq!(a1.identity().commitment_c, a2.identity().commitment_c);
    }

    #[test]
    fn signing_is_stable_and_verifies() {
        let r = [0x33u8; 32];
        let host = [0x44u8; 32];
        let anchor = birth_single(&r, ctx(), &host).expect("birth");

        let h_n = [0xA1u8; 32];
        let payload = [0xB2u8; 32];
        let policy = b"offline-bearer/v1";

        let s1 = anchor
            .sign_transition(&h_n, &payload, policy)
            .expect("sign");
        let s2 = anchor
            .sign_transition(&h_n, &payload, policy)
            .expect("sign");
        assert_eq!(s1, s2, "SPHINCS+ signing is deterministic given the key");

        let ok = verify_transition(anchor.identity(), &h_n, &payload, policy, &s1).expect("verify");
        assert!(ok, "genuine signature must verify");
    }

    #[test]
    fn verify_rejects_wrong_challenge() {
        let r = [0x55u8; 32];
        let host = [0x66u8; 32];
        let anchor = birth_single(&r, ctx(), &host).expect("birth");

        let h_n = [0x01u8; 32];
        let payload = [0x02u8; 32];
        let policy = b"p";
        let sig = anchor
            .sign_transition(&h_n, &payload, policy)
            .expect("sign");

        let h_other = [0x09u8; 32];
        let ok =
            verify_transition(anchor.identity(), &h_other, &payload, policy, &sig).expect("verify");
        assert!(!ok, "signature must not verify over a different transition");
    }

    #[test]
    fn clone_with_different_root_is_rejected() {
        let host = [0x77u8; 32];
        let original = birth_single(&[0xAAu8; 32], ctx(), &host).expect("birth");
        let clone = birth_single(&[0xABu8; 32], ctx(), &host).expect("birth");

        // A different internal root yields a different anchor identity.
        assert_ne!(original.identity().id_anchor, clone.identity().id_anchor);
        assert_ne!(original.identity().sphincs_pk, clone.identity().sphincs_pk);

        let h_n = [0x10u8; 32];
        let payload = [0x20u8; 32];
        let policy = b"p";
        let sig = original
            .sign_transition(&h_n, &payload, policy)
            .expect("sign");

        // The genuine signature verifies only under the genuine identity.
        assert!(verify_transition(original.identity(), &h_n, &payload, policy, &sig).unwrap());
        assert!(
            !verify_transition(clone.identity(), &h_n, &payload, policy, &sig).unwrap(),
            "a copy on a different root must not pass under its own identity"
        );
    }

    #[test]
    fn host_contribution_changes_the_anchor() {
        // Same internal root, different host contribution, different anchor.
        // The host cannot be cut out: it co determines the state.
        let r = [0x5Au8; 32];
        let a1 = birth_single(&r, ctx(), &[0x01u8; 32]).expect("birth");
        let a2 = birth_single(&r, ctx(), &[0x02u8; 32]).expect("birth");
        assert_ne!(a1.identity().id_anchor, a2.identity().id_anchor);
    }

    #[test]
    fn sealing_hides_the_drive() {
        // Build an element to seal to.
        let e = element_init(&[0xC0u8; 32]).expect("init");
        let drive_value = [0x7Eu8; 32];
        let seal_seed = [0x01u8; 32];

        let (ct, sealed) = seal_to_peer(&e.kem_pk, &drive_value, &seal_seed).expect("seal");
        assert_ne!(sealed, drive_value, "sealed bytes must not equal the drive");

        let opened = open_from_peer(&e.kem_sk, &ct, &sealed).expect("open");
        assert_eq!(
            opened, drive_value,
            "the holder of the KEM secret recovers it"
        );

        // A different element cannot open it to the same value.
        let other = element_init(&[0xC1u8; 32]).expect("init");
        let wrong = open_from_peer(&other.kem_sk, &ct, &sealed).expect("open");
        assert_ne!(
            wrong, drive_value,
            "a wrong secret must not recover the drive"
        );
    }

    #[test]
    fn cross_driven_requires_both_signatures() {
        let set = birth_pair(
            &[0x01u8; 32],
            &[0x02u8; 32],
            ctx(),
            b"transcript/v1",
            &[0x10u8; 32],
            &[0x11u8; 32],
            &[0x12u8; 32],
            &[0x13u8; 32],
        )
        .expect("pair birth");

        let h_n = [0xD1u8; 32];
        let payload = [0xD2u8; 32];
        let policy = b"p";

        let (s_a, s_b) = sign_transition_set(&set, &h_n, &payload, policy).expect("sign set");

        let a = set.anchor_a.identity();
        let b = set.anchor_b.identity();

        assert!(
            verify_transition_set(a, b, &h_n, &payload, policy, &s_a, &s_b).unwrap(),
            "both genuine signatures must verify"
        );

        // Swapping the two signatures fails: each verifies only under its own
        // identity.
        assert!(
            !verify_transition_set(a, b, &h_n, &payload, policy, &s_b, &s_a).unwrap(),
            "signatures are not interchangeable across the two anchors"
        );

        // One good and one absent fails.
        let bad = vec![0u8; s_b.len()];
        assert!(
            !verify_transition_set(a, b, &h_n, &payload, policy, &s_a, &bad).unwrap(),
            "a missing second signature must fail the set"
        );
    }

    #[test]
    fn cross_driven_is_deterministic() {
        let args = (
            [0x01u8; 32],
            [0x02u8; 32],
            b"transcript/v1".to_vec(),
            [0x10u8; 32],
            [0x11u8; 32],
            [0x12u8; 32],
            [0x13u8; 32],
        );
        let s1 = birth_pair(
            &args.0,
            &args.1,
            ctx(),
            &args.2,
            &args.3,
            &args.4,
            &args.5,
            &args.6,
        )
        .expect("pair");
        let s2 = birth_pair(
            &args.0,
            &args.1,
            ctx(),
            &args.2,
            &args.3,
            &args.4,
            &args.5,
            &args.6,
        )
        .expect("pair");
        assert_eq!(
            s1.anchor_a.identity().id_anchor,
            s2.anchor_a.identity().id_anchor
        );
        assert_eq!(
            s1.anchor_b.identity().id_anchor,
            s2.anchor_b.identity().id_anchor
        );
    }

    #[test]
    fn cross_driven_clone_rejection() {
        let transcript = b"transcript/v1";
        let set = birth_pair(
            &[0x01u8; 32],
            &[0x02u8; 32],
            ctx(),
            transcript,
            &[0x10u8; 32],
            &[0x11u8; 32],
            &[0x12u8; 32],
            &[0x13u8; 32],
        )
        .expect("pair");

        // Re birth the pair with a different root for B. Because A's state is
        // driven by B, and B's identity changes, the cloned B's anchor differs
        // and its signatures do not verify under the original B identity.
        let cloned = birth_pair(
            &[0x01u8; 32],
            &[0x03u8; 32],
            ctx(),
            transcript,
            &[0x10u8; 32],
            &[0x11u8; 32],
            &[0x12u8; 32],
            &[0x13u8; 32],
        )
        .expect("pair");

        assert_ne!(
            set.anchor_b.identity().id_anchor,
            cloned.anchor_b.identity().id_anchor,
            "a different root for B yields a different B anchor"
        );

        let h_n = [0xE1u8; 32];
        let payload = [0xE2u8; 32];
        let policy = b"p";
        let s_b_clone = cloned
            .anchor_b
            .sign_transition(&h_n, &payload, policy)
            .expect("sign");

        assert!(
            !verify_transition(set.anchor_b.identity(), &h_n, &payload, policy, &s_b_clone)
                .unwrap(),
            "the cloned B must not pass under the original B identity"
        );
    }
}

// ============================ Adversarial tests =============================
//
// Each test below encodes a concrete attack and asserts the attack fails. The
// attacker is assumed to control the host, to be able to modify any value the
// host relays, and to hold the full public record plus any number of past
// signatures. The one thing the attacker never holds is an element internal
// root.

#[cfg(test)]
mod adversarial {
    use super::*;
    use std::collections::HashSet;

    fn ctx() -> &'static [u8] {
        b"device-context/test"
    }

    // Recompute sigma the way single element birth does, for an attacker who
    // supplies a guessed root. Used to show the root is the only missing input.
    fn sigma_from(r: &[u8; 32], k_user: &[u8], c: &[u8; 32], device_context: &[u8]) -> [u8; 32] {
        let mut ikm = Vec::new();
        ikm.extend_from_slice(r);
        ikm.extend_from_slice(k_user);
        ikm.extend_from_slice(c);
        let v = extract_and_expand(b"DSM/anchor/sigma\0", &ikm, device_context, 32);
        let mut s = [0u8; 32];
        s.copy_from_slice(&v);
        s
    }

    fn forge_from_sigma(sigma: &[u8; 32], h: &[u8; 32], p: &[u8; 32], policy: &[u8]) -> Vec<u8> {
        let seed = domain_hash_bytes("DSM/anchor/sphincs-seed", sigma);
        let kp = sphincs::generate_keypair_from_seed(ANCHOR_SPHINCS_VARIANT, &seed).unwrap();
        let ch = transition_challenge(h, p, policy);
        sphincs::sign(ANCHOR_SPHINCS_VARIANT, &kp.secret_key, &ch).unwrap()
    }

    /// The strongest attack: the attacker has the whole public record and a
    /// long history of signatures, and still cannot sign a fresh transition.
    #[test]
    fn attacker_with_public_record_and_history_cannot_sign() {
        let victim = birth_single(&[0x21u8; 32], ctx(), &[0x22u8; 32]).expect("birth");
        let id = victim.identity().clone();

        let policy = b"p";
        let mut history = Vec::new();
        for i in 0..16u8 {
            let h = [i; 32];
            let p = [i ^ 0xFF; 32];
            let s = victim.sign_transition(&h, &p, policy).unwrap();
            assert!(verify_transition(&id, &h, &p, policy, &s).unwrap());
            history.push((h, p, s));
        }

        let h_star = [0xAB; 32];
        let p_star = [0xCD; 32];

        // (a) Replaying any past signature on the fresh challenge fails.
        for (_, _, s) in &history {
            assert!(!verify_transition(&id, &h_star, &p_star, policy, s).unwrap());
        }
        // (b) A garbage signature of the right length fails.
        let len = history[0].2.len();
        assert!(!verify_transition(&id, &h_star, &p_star, policy, &vec![0u8; len]).unwrap());
        // (c) A signature from an anchor the attacker controls fails under the
        // victim identity.
        let attacker = birth_single(&[0x99u8; 32], ctx(), &[0x98u8; 32]).unwrap();
        let s_att = attacker.sign_transition(&h_star, &p_star, policy).unwrap();
        assert!(!verify_transition(&id, &h_star, &p_star, policy, &s_att).unwrap());
    }

    /// The host knows k_user, because it ran the encapsulation. It still cannot
    /// reach sigma, because it does not hold the root.
    #[test]
    fn malicious_host_knows_k_user_but_not_sigma() {
        let r = [0x31u8; 32];
        let host_seed = [0x32u8; 32];
        let victim = birth_single(&r, ctx(), &host_seed).expect("birth");
        let c = victim.identity().commitment_c;

        // The host re-derives the exact k_user it delivered.
        let (k_user, _ct) =
            kyber_encapsulate_deterministic(&victim.identity().kem_pk, &host_seed).unwrap();

        // Positive control: with the real root, the host's own values reproduce
        // sigma exactly. So the only missing input is the root.
        let sigma_real = sigma_from(&r, &k_user, &c, ctx());
        assert_eq!(
            sigma_real, victim.sigma,
            "formula check: root is the only missing input"
        );

        // Attack: lacking the root, the host guesses zero and misses.
        let sigma_guess = sigma_from(&[0u8; 32], &k_user, &c, ctx());
        assert_ne!(sigma_guess, victim.sigma);

        let h = [0x01; 32];
        let p = [0x02; 32];
        let forged = forge_from_sigma(&sigma_guess, &h, &p, b"p");
        assert!(
            !verify_transition(victim.identity(), &h, &p, b"p", &forged).unwrap(),
            "a host that knows k_user but not the root cannot forge"
        );
    }

    /// A malicious relay that tampers with a sealed drive cannot steer it to a
    /// chosen value. The best it can do is corrupt it, which is detectable
    /// because the victim's anchor then diverges.
    #[test]
    fn relay_tampering_with_sealed_drive_is_fail_closed() {
        let r_a = [0x41u8; 32];
        let r_b = [0x42u8; 32];
        let transcript = b"t";
        let eb = element_init(&r_b).unwrap();
        let pre_b = domain_hash_bytes("DSM/anchor/pre-id", &eb.kem_pk);
        let d_a_to_b = drive(&r_a, "DSM/anchor/drive-a-to-b", &pre_b, transcript);
        let (ct_ab, sealed_ab) = seal_to_peer(&eb.kem_pk, &d_a_to_b, &[0x43u8; 32]).unwrap();

        // Honest delivery recovers the true drive.
        assert_eq!(
            open_from_peer(&eb.kem_sk, &ct_ab, &sealed_ab).unwrap(),
            d_a_to_b
        );

        // Flip a bit in the sealed bytes: victim opens a DIFFERENT value, and
        // not a value the attacker chose.
        let mut sealed_t = sealed_ab;
        sealed_t[0] ^= 0x01;
        let opened_t = open_from_peer(&eb.kem_sk, &ct_ab, &sealed_t).unwrap();
        assert_ne!(opened_t, d_a_to_b, "tamper changes the delivered drive");
        let target = [0x42u8; 32];
        assert_ne!(
            opened_t, target,
            "relay cannot steer the drive to a chosen value"
        );

        // Flip a bit in the KEM ciphertext: ML-KEM implicit rejection yields a
        // different shared secret, so a different drive again.
        let mut ct_t = ct_ab.clone();
        ct_t[0] ^= 0x01;
        let opened_ct = open_from_peer(&eb.kem_sk, &ct_t, &sealed_ab).unwrap();
        assert_ne!(
            opened_ct, d_a_to_b,
            "ciphertext tamper changes the delivered drive"
        );
    }

    /// A sealed drive captured from one pair does not open in another element.
    #[test]
    fn sealed_drive_does_not_replay_into_another_pair() {
        let transcript = b"t";
        let r_a = [0x51u8; 32];
        let r_b1 = [0x52u8; 32];
        let r_b2 = [0x53u8; 32];

        let eb1 = element_init(&r_b1).unwrap();
        let eb2 = element_init(&r_b2).unwrap();

        let pre_b1 = domain_hash_bytes("DSM/anchor/pre-id", &eb1.kem_pk);
        let d_a_to_b1 = drive(&r_a, "DSM/anchor/drive-a-to-b", &pre_b1, transcript);
        let (ct, sealed) = seal_to_peer(&eb1.kem_pk, &d_a_to_b1, &[0x54u8; 32]).unwrap();

        // A different element opens the captured blob to garbage.
        let opened_wrong = open_from_peer(&eb2.kem_sk, &ct, &sealed).unwrap();
        assert_ne!(opened_wrong, d_a_to_b1);
        // The intended element still opens it correctly.
        assert_eq!(
            open_from_peer(&eb1.kem_sk, &ct, &sealed).unwrap(),
            d_a_to_b1
        );
    }

    /// Signature integrity: a flipped byte, a truncation, or an empty buffer
    /// are all rejected.
    #[test]
    fn signature_bit_flip_and_truncation_rejected() {
        let anchor = birth_single(&[0x61u8; 32], ctx(), &[0x62u8; 32]).unwrap();
        let h = [0x07; 32];
        let p = [0x08; 32];
        let policy = b"p";
        let mut sig = anchor.sign_transition(&h, &p, policy).unwrap();
        assert!(verify_transition(anchor.identity(), &h, &p, policy, &sig).unwrap());

        let mid = sig.len() / 2;
        sig[mid] ^= 0x01;
        assert!(!verify_transition(anchor.identity(), &h, &p, policy, &sig).unwrap());
        sig[mid] ^= 0x01;

        let trunc = &sig[..sig.len() - 1];
        assert!(!verify_transition(anchor.identity(), &h, &p, policy, trunc).unwrap());
        assert!(!verify_transition(anchor.identity(), &h, &p, policy, &[]).unwrap());
    }

    /// The published record must not contain the hidden state or the secret
    /// signing key.
    #[test]
    fn no_secret_material_in_public_record() {
        let anchor = birth_single(&[0x71u8; 32], ctx(), &[0x72u8; 32]).unwrap();
        let id = anchor.identity();
        let mut public = Vec::new();
        public.extend_from_slice(&id.id_anchor);
        public.extend_from_slice(&id.sphincs_pk);
        public.extend_from_slice(&id.kem_pk);
        public.extend_from_slice(&id.commitment_c);

        for w in public.windows(32) {
            assert_ne!(w, &anchor.sigma[..], "sigma leaked into the public record");
        }
        let sk_head = &anchor.sphincs_sk[..32];
        for w in public.windows(32) {
            assert_ne!(
                w, sk_head,
                "secret key material leaked into the public record"
            );
        }
    }

    /// One bit in the root avalanches the identity.
    #[test]
    fn id_anchor_avalanches_on_root_bit_flip() {
        let r = [0x81u8; 32];
        let host = [0x82u8; 32];
        let a = birth_single(&r, ctx(), &host).unwrap();
        let mut r2 = r;
        r2[0] ^= 0x01;
        let b = birth_single(&r2, ctx(), &host).unwrap();
        let diff = a
            .identity()
            .id_anchor
            .iter()
            .zip(b.identity().id_anchor.iter())
            .filter(|(x, y)| x != y)
            .count();
        assert!(
            diff > 8,
            "one bit in the root must avalanche the identity, got {diff}"
        );
    }

    /// Distinct roots give distinct identities across a batch.
    #[test]
    fn distinct_roots_give_distinct_identities_in_batch() {
        let host = [0x90u8; 32];
        let mut ids = HashSet::new();
        for i in 0..64u16 {
            let mut r = [0u8; 32];
            r[0] = i as u8;
            r[1] = (i >> 8) as u8;
            let a = birth_single(&r, ctx(), &host).unwrap();
            assert!(
                ids.insert(a.identity().id_anchor),
                "identity collision at {i}"
            );
        }
    }

    /// Different host contribution changes the hidden state, not just the id.
    #[test]
    fn host_seed_independence_changes_sigma() {
        let r = [0xA1u8; 32];
        let a = birth_single(&r, ctx(), &[0x01u8; 32]).unwrap();
        let b = birth_single(&r, ctx(), &[0x02u8; 32]).unwrap();
        assert_ne!(
            a.sigma, b.sigma,
            "different host contribution must change the state"
        );
        assert_ne!(a.identity().id_anchor, b.identity().id_anchor);
    }

    /// An attacker who controls only one element cannot satisfy both legs of a
    /// cross driven set.
    #[test]
    fn set_rejects_one_signer_doing_both_legs() {
        let set = birth_pair(
            &[0xB1u8; 32],
            &[0xB2u8; 32],
            ctx(),
            b"t",
            &[0x10u8; 32],
            &[0x11u8; 32],
            &[0x12u8; 32],
            &[0x13u8; 32],
        )
        .unwrap();
        let h = [0x01; 32];
        let p = [0x02; 32];
        let s_a = set.anchor_a.sign_transition(&h, &p, b"p").unwrap();
        assert!(
            !verify_transition_set(
                set.anchor_a.identity(),
                set.anchor_b.identity(),
                &h,
                &p,
                b"p",
                &s_a,
                &s_a
            )
            .unwrap(),
            "one element cannot satisfy both legs of the set"
        );
    }

    /// The walk is distinct per root and sensitive to a single bit.
    #[test]
    fn walk_is_distinct_per_root() {
        let w1 = walk(&[0xC1u8; 32]);
        let w2 = walk(&[0xC2u8; 32]);
        assert_ne!(w1, w2);
        let mut r = [0xC1u8; 32];
        r[31] ^= 0x01;
        let w3 = walk(&r);
        assert_ne!(w1, w3, "a one bit change in the root changes the walk");
    }

    /// Diagnostic: characterize how the raw SPHINCS+ primitive responds to
    /// single byte flips across the signature. Isolated from the anchor so it
    /// measures the primitive itself. Prints a summary line tagged SPHINCS_DIAG.
    #[test]
    fn diagnose_sphincs_bitflip() {
        let v = SphincsVariant::SPX256s;
        let kp = sphincs::generate_keypair_from_seed(v, &[0x5Cu8; 32]).unwrap();
        let msg = [0xA7u8; 32];
        let sig = sphincs::sign(v, &kp.secret_key, &msg).unwrap();
        assert!(
            sphincs::verify(v, &kp.public_key, &msg, &sig).unwrap(),
            "honest signature must verify"
        );
        let n = sig.len();

        let probe = [
            0usize,
            16,
            31,
            32,
            100,
            5000,
            n / 2,
            (n * 3) / 4,
            n - 100,
            n - 1,
        ];
        let mut still_valid = Vec::new();
        for &pos in &probe {
            let mut s = sig.clone();
            s[pos] ^= 0x01;
            if sphincs::verify(v, &kp.public_key, &msg, &s).unwrap() {
                still_valid.push(pos);
            }
        }
        let mut window_valid = 0usize;
        for pos in 0..32usize {
            let mut s = sig.clone();
            s[pos] ^= 0x01;
            if sphincs::verify(v, &kp.public_key, &msg, &s).unwrap() {
                window_valid += 1;
            }
        }
        println!(
            "SPHINCS_DIAG len={} probe_still_valid={:?} first32_still_valid={}/32",
            n, still_valid, window_valid
        );
    }

    /// Diagnostic v2: is the malleable byte a fixed structural offset, or
    /// specific to one signature? Scans a window around 14896 for two messages
    /// and two keys, and tests all 8 bit positions at 14896.
    #[test]
    fn diagnose_sphincs_malleable_window() {
        let v = SphincsVariant::SPX256s;
        let scan = |seed: [u8; 32], msg: [u8; 32]| -> Vec<usize> {
            let kp = sphincs::generate_keypair_from_seed(v, &seed).unwrap();
            let sig = sphincs::sign(v, &kp.secret_key, &msg).unwrap();
            assert!(sphincs::verify(v, &kp.public_key, &msg, &sig).unwrap());
            let mut mall = Vec::new();
            for pos in 14880..14913usize {
                let mut s = sig.clone();
                s[pos] ^= 0x01;
                if sphincs::verify(v, &kp.public_key, &msg, &s).unwrap() {
                    mall.push(pos);
                }
            }
            mall
        };
        let a1 = scan([0x5C; 32], [0xA7; 32]);
        let a2 = scan([0x5C; 32], [0x42; 32]);
        let b1 = scan([0x11; 32], [0xA7; 32]);
        println!(
            "SPHINCS_MALL window=14880..14913 A_msg1={:?} A_msg2={:?} B_msg1={:?}",
            a1, a2, b1
        );

        let kp = sphincs::generate_keypair_from_seed(v, &[0x5C; 32]).unwrap();
        let sig = sphincs::sign(v, &kp.secret_key, &[0xA7; 32]).unwrap();
        let mut bits = Vec::new();
        for bit in 0..8u8 {
            let mut s = sig.clone();
            s[14896] ^= 1 << bit;
            if sphincs::verify(v, &kp.public_key, &[0xA7; 32], &s).unwrap() {
                bits.push(bit);
            }
        }
        println!("SPHINCS_MALL_BITS pos=14896 valid_bits={:?}", bits);
    }

    /// Diagnostic v3: bound the unchecked span within hypertree layer 1, and
    /// probe whether every hypertree layer has the same hole at the element 59
    /// offset. Prints SPHINCS_SPAN and SPHINCS_LAYERS.
    #[test]
    fn diagnose_sphincs_span_and_layers() {
        let v = SphincsVariant::SPX256s;
        let kp = sphincs::generate_keypair_from_seed(v, &[0x5C; 32]).unwrap();
        let sig = sphincs::sign(v, &kp.secret_key, &[0xA7; 32]).unwrap();
        assert!(sphincs::verify(v, &kp.public_key, &[0xA7; 32], &sig).unwrap());

        let valid_at = |pos: usize| -> bool {
            let mut s = sig.clone();
            s[pos] ^= 0x01;
            sphincs::verify(v, &kp.public_key, &[0xA7; 32], &s).unwrap()
        };

        // Bound the malleable span across all of hypertree layer 1 (12992..15392).
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        let mut start: Option<usize> = None;
        for pos in 12992..15392usize {
            if valid_at(pos) {
                if start.is_none() {
                    start = Some(pos);
                }
            } else if let Some(st) = start.take() {
                ranges.push((st, pos));
            }
        }
        if let Some(st) = start.take() {
            ranges.push((st, 15392));
        }
        println!("SPHINCS_SPAN layer1 malleable_ranges={:?}", ranges);

        // Probe the element 59 offset in each of the 8 hypertree layers.
        let mut layers = Vec::new();
        for l in 0..8usize {
            let pos = 10592 + l * 2400 + 59 * 32;
            layers.push((l, valid_at(pos)));
        }
        println!("SPHINCS_LAYERS element59_offset_malleable={:?}", layers);
    }
}
