//! WOTS (Winternitz one-time signature) over BLAKE3 — the per-root-advance
//! hardware-witness signature scheme (`StepKeyGen` / `StepSign` / `StepVerify`,
//! §9).
//!
//! The witness key signs exactly one digest: one certificate message `M` per
//! root advance, derived from a fresh MACANDD output `W` (§8). A one-time
//! signature is therefore the right primitive — the Merkle-hypertree machinery
//! of a many-time scheme (SPHINCS+) buys nothing here. Hash-based ⇒ post-quantum;
//! deterministic from the 32-byte seed `K` (which is `sk_hw`); BLAKE3-only ⇒
//! cheap on the RP2350 and byte-identical for the firmware producer and any
//! verifier.
//!
//! Parameters: `n = 32` (BLAKE3-256), `w = 16` (4-bit digits), `len1 = 64`
//! message digits, `len2 = 3` checksum digits, `len = 67` chains. The signature
//! is `67·32 = 2144` bytes; the public key is the 32-byte hash of the 67 chain
//! tops, and `P_hw = H("DSM/tropic/pk-hash/v1" ‖ pk_hw)`.
//!
//! Security: forging a signature on any `d' ≠ d` requires advancing at least one
//! hash chain backwards (a preimage). The Winternitz checksum `Σ(w-1 - dᵢ)`
//! guarantees that increasing any message digit forces a checksum digit to
//! decrease (standard positional base-w argument), so every forgery needs a
//! preimage of BLAKE3. One-time use is enforced by the protocol (one signature
//! per `sk_hw`).

extern crate alloc;
use alloc::vec::Vec;

use crate::domain;
use crate::hash::{h, kdf};
use crate::tropic::WitnessSig;
use crate::util::ct_eq_32;

const W: u32 = 16; // Winternitz parameter
const LG_W: u32 = 4; // log2(W)
const LEN1: usize = 64; // ceil(256 / lg_w): message digits
const LEN2: usize = 3; // checksum digits (csum ≤ 64·15 = 960 < 16³)
const LEN: usize = LEN1 + LEN2; // 67 chains
const N: usize = 32; // chain element size
const SIG_LEN: usize = LEN * N; // 2144

/// One BLAKE3 chain step: `F(x) = H("DSM/anchor/wots-chain/v1" ‖ x)`.
fn chain(mut x: [u8; N], steps: u32) -> [u8; N] {
    for _ in 0..steps {
        x = h(domain::WOTS_CHAIN_V1, &[&x]);
    }
    x
}

/// The `len` base-w digits (64 message + 3 checksum) of a 32-byte digest.
fn digits(d: &[u8; 32]) -> [u8; LEN] {
    let mut out = [0u8; LEN];
    // Message digits: high nibble then low nibble of each byte.
    for (i, &b) in d.iter().enumerate() {
        out[2 * i] = b >> 4;
        out[2 * i + 1] = b & 0x0f;
    }
    // Checksum = Σ (w-1 - digit) over the message digits.
    let mut csum: u32 = 0;
    for &dg in out[..LEN1].iter() {
        csum += (W - 1) - dg as u32;
    }
    // 3 big-endian base-w checksum digits.
    out[LEN1] = ((csum >> (2 * LG_W)) & (W - 1)) as u8;
    out[LEN1 + 1] = ((csum >> LG_W) & (W - 1)) as u8;
    out[LEN1 + 2] = (csum & (W - 1)) as u8;
    out
}

/// i-th chain secret: `sk_i = KDF(seed, "DSM/anchor/wots-sk/v1" ‖ i)`.
fn chain_secret(seed: &[u8; 32], i: usize) -> [u8; N] {
    kdf(seed, domain::WOTS_SK_V1, &[&(i as u16).to_le_bytes()])
}

/// Compress the 67 chain tops into the 32-byte public key.
fn compress(tops: &[[u8; N]; LEN]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(LEN * N);
    for t in tops.iter() {
        buf.extend_from_slice(t);
    }
    h(domain::WOTS_PK_V1, &[&buf])
}

/// The WOTS-over-BLAKE3 witness signature scheme.
pub struct WotsBlake3;

impl WitnessSig for WotsBlake3 {
    /// `sk = K` (the 32-byte seed); `pk` = the 32-byte compressed public key.
    fn keygen(seed: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        let mut tops = [[0u8; N]; LEN];
        for (i, top) in tops.iter_mut().enumerate() {
            *top = chain(chain_secret(seed, i), W - 1);
        }
        (seed.to_vec(), compress(&tops).to_vec())
    }

    /// `σ` = each chain advanced from its secret to its message/checksum digit.
    fn sign(sk: &[u8], digest: &[u8; 32]) -> Vec<u8> {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&sk[..32]);
        let dg = digits(digest);
        let mut sig = Vec::with_capacity(SIG_LEN);
        for (i, &d_i) in dg.iter().enumerate() {
            let v = chain(chain_secret(&seed, i), d_i as u32);
            sig.extend_from_slice(&v);
        }
        sig
    }

    /// Recompute the chain tops from `σ` and the digits, hash, compare to `pk`.
    fn verify(pk: &[u8], digest: &[u8; 32], sig: &[u8]) -> bool {
        if pk.len() != 32 || sig.len() != SIG_LEN {
            return false;
        }
        let dg = digits(digest);
        let mut tops = [[0u8; N]; LEN];
        for (i, &d_i) in dg.iter().enumerate() {
            let mut v = [0u8; N];
            v.copy_from_slice(&sig[i * N..(i + 1) * N]);
            tops[i] = chain(v, (W - 1) - d_i as u32);
        }
        let pk_re = compress(&tops);
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(pk);
        ct_eq_32(&pk_re, &pk_arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let seed = [7u8; 32];
        let (sk, pk) = WotsBlake3::keygen(&seed);
        assert_eq!(sk, seed.to_vec());
        assert_eq!(pk.len(), 32);
        let d = h("test/digest", &[b"hello"]);
        let sig = WotsBlake3::sign(&sk, &d);
        assert_eq!(sig.len(), SIG_LEN);
        assert!(WotsBlake3::verify(&pk, &d, &sig));
    }

    #[test]
    fn rejects_wrong_digest_tampered_sig_and_pk() {
        let seed = [9u8; 32];
        let (sk, pk) = WotsBlake3::keygen(&seed);
        let d = h("test/digest", &[b"msg"]);
        let sig = WotsBlake3::sign(&sk, &d);

        // Wrong digest.
        let d2 = h("test/digest", &[b"other"]);
        assert!(!WotsBlake3::verify(&pk, &d2, &sig));

        // Tampered signature.
        let mut sig_bad = sig.clone();
        sig_bad[0] ^= 0xFF;
        assert!(!WotsBlake3::verify(&pk, &d, &sig_bad));

        // Wrong public key.
        let (_, pk2) = WotsBlake3::keygen(&[10u8; 32]);
        assert!(!WotsBlake3::verify(&pk2, &d, &sig));

        // Wrong-length inputs.
        assert!(!WotsBlake3::verify(&pk, &d, &sig[..SIG_LEN - 1]));
        assert!(!WotsBlake3::verify(&[0u8; 31], &d, &sig));
    }

    #[test]
    fn deterministic_from_seed() {
        let seed = [3u8; 32];
        let (_, pk_a) = WotsBlake3::keygen(&seed);
        let (_, pk_b) = WotsBlake3::keygen(&seed);
        assert_eq!(pk_a, pk_b, "keygen must be deterministic from the seed");
        let d = h("test/digest", &[b"x"]);
        assert_eq!(WotsBlake3::sign(&seed, &d), WotsBlake3::sign(&seed, &d));
    }

    #[test]
    fn forgery_to_a_higher_digit_is_rejected() {
        // Advancing a revealed chain forward (raising a message digit) must fail
        // because the checksum digit would need to go backward (a preimage).
        let seed = [1u8; 32];
        let (_, pk) = WotsBlake3::keygen(&seed);
        // Pick a digest whose first nibble is < w-1 so it can be advanced.
        let mut d = h("test/digest", &[b"forge"]);
        d[0] &= 0x0f; // high nibble 0 -> advanceable
        let sig = WotsBlake3::sign(&seed, &d);
        // Forge: advance chain 0 one step (claim digit+1) without fixing checksum.
        let mut forged = sig.clone();
        let mut c0 = [0u8; N];
        c0.copy_from_slice(&forged[..N]);
        let c0_adv = chain(c0, 1);
        forged[..N].copy_from_slice(&c0_adv);
        let mut d_forged = d;
        d_forged[0] = (d_forged[0] & 0x0f) | (((d[0] >> 4) + 1) << 4);
        assert!(
            !WotsBlake3::verify(&pk, &d_forged, &forged),
            "checksum must defeat a forward-advanced forgery"
        );
    }
}
