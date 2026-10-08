// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM key schedule KS1: Extract-then-Expand.
//!
//! Every secret a wallet derives comes from one of three pseudorandom keys,
//! each the output of a single HKDF-Extract (HMAC-BLAKE3, RFC 5869) under a
//! **fixed protocol salt**. Domain separation lives in the Expand `info`,
//! never in the Extract salt:
//!
//! ```text
//! mnemonic (24 words, 256-bit) -> wallet_seed = BIP39 seed
//! PRK_w  = Extract("DSM/kdf/wallet-root/v1" 0x00, wallet_seed)
//!   genesis_nonce   = Expand(PRK_w, "DSM/genesis-public-nonce/v3"   0x00 lp(network_id) idx)   [PUBLIC]
//!   GRK_seed        = Expand(PRK_w, "DSM/genesis-root-authority/v2" 0x00 lp(network_id) idx ver)
//!   AttA            = Expand(PRK_w, "DSM/atta/v3"                   0x00 G slot)               [PUBLIC]
//!   device_seed     = Expand(PRK_w, "DSM/device-seed/v3"            0x00 G slot)
//!   s0              = Expand(PRK_w, "DSM/s0/v3"                     0x00 G slot aph)
//!   sdk_entropy     = Expand(PRK_w, "DSM/sdk-entropy/v3"            0x00 DevID G)
//!   recovery_aead   = Expand(PRK_w, "DSM/recovery-aead/v2"          0x00)
//!   recovery_auth   = Expand(PRK_w, "DSM/recovery-authority/v2"     0x00)
//! PRK_d  = Extract("DSM/kdf/device-root/v1" 0x00, device_seed)
//!   AK_seed         = Expand(PRK_d, "DSM/device-ak/v3"              0x00 aph)
//! PRK_s0 = Extract("DSM/kdf/s0-root/v1" 0x00, s0)
//!   Smaster         = Expand(PRK_s0, "DSM/Smaster/v3"               0x00 G DevID aph)
//!   K_at_rest       = Expand(PRK_s0, "DSM/chain-head-at-rest/v3"    0x00 G DevID)
//! Smaster is the key of keyed BLAKE3 for everything below it:
//!   EK seed         = keyed-BLAKE3(Smaster, "DSM/ek/v1" 0x00 alg_id chain_id h_n C_pre k_step)
//!   ML-KEM coins    = keyed-BLAKE3(Smaster, "DSM/kyber-coins/v1" 0x00 ...)
//!   ML-KEM seed     = keyed-BLAKE3(Smaster, "DSM/ml-kem-identity/v1" 0x00 "ML-KEM-768")
//! ```
//!
//! `lp(x)` is `len(x) as u32 LE ‖ x`; `idx`, `ver`, `slot` are `u32 LE`; `G`,
//! `DevID`, `aph` are 32 bytes. Every label is a NUL-free domain tag followed
//! by `0x00`, so distinct labels give distinct `info` strings whatever the
//! fields, and within one label every field is fixed-width or length-prefixed,
//! so the fields are recoverable from `info`.
//!
//! Each secret is used through exactly one interface: `wallet_seed` and the
//! two intermediate seeds only as Extract input, the three PRKs only as HMAC
//! keys of Expand, and `Smaster` only as the keyed-BLAKE3 key. Public values
//! (the nonce, AttA, the AK, GRK and ML-KEM public keys, DevID)
//! are all functions of Expand or keyed-BLAKE3 outputs.
//!
//! This replaced the earlier schedule, in which every derivation was
//! `HKDF(salt = domain tag, IKM = secret)`: sibling outputs were HMACs of one
//! secret under different public keys, Smaster also fed an unkeyed hash for
//! the ML-KEM key, and `s0` also served as a keyed-BLAKE3 key. Identities from
//! that schedule are not migrated (DSM beta does not migrate).

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::common::domain_tags::{
    TAG_DSM_ATTA_V3, TAG_DSM_CHAIN_HEAD_AT_REST_V3, TAG_DSM_DEVICE_AK_V3, TAG_DSM_DEVICE_SEED_V3,
    TAG_DSM_GENESIS_NONCE_V3, TAG_DSM_GENESIS_ROOT_AUTHORITY_V2, TAG_DSM_KDF_DEVICE_ROOT_V1,
    TAG_DSM_KDF_S0_ROOT_V1, TAG_DSM_KDF_WALLET_ROOT_V1, TAG_DSM_ML_KEM_IDENTITY_V1,
    TAG_DSM_RECOVERY_AEAD_V2, TAG_DSM_RECOVERY_AUTHORITY_V2, TAG_DSM_S0_V3, TAG_DSM_SDK_ENTROPY_V3,
    TAG_DSM_SMASTER_V3,
};
use crate::crypto::domain::TaggedHashDomain;
use crate::crypto::hkdf;

/// The identifier of this key schedule.
pub const KEY_SCHEDULE: &str = "KS1";

/// A pseudorandom key: the output of one HKDF-Extract. Only ever used as the
/// HMAC key of Expand.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Prk([u8; 32]);

fn tag_nul(tag: TaggedHashDomain<'_>) -> Vec<u8> {
    let mut v = Vec::with_capacity(tag.source_bytes().len() + 1);
    v.extend_from_slice(tag.source_bytes());
    v.push(0u8);
    v
}

fn extract(salt: TaggedHashDomain<'_>, ikm: &[u8]) -> Prk {
    let mut s = tag_nul(salt);
    let prk = Prk(hkdf::extract(&s, ikm));
    s.zeroize();
    prk
}

/// The Expand `info` string: `label ‖ 0x00 ‖ fields`.
pub fn info(label: TaggedHashDomain<'_>, fields: &[&[u8]]) -> Vec<u8> {
    let mut v = tag_nul(label);
    for f in fields {
        v.extend_from_slice(f);
    }
    v
}

fn expand32(prk: &Prk, label: TaggedHashDomain<'_>, fields: &[&[u8]]) -> [u8; 32] {
    let mut inf = info(label, fields);
    let mut okm = hkdf::expand(&prk.0, &inf, 32);
    let out: [u8; 32] = okm
        .as_slice()
        .try_into()
        .expect("HKDF-Expand returns exactly the 32 bytes asked for");
    okm.zeroize();
    inf.zeroize();
    out
}

/// `len(x) as u32 LE ‖ x`.
fn lp(x: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + x.len());
    v.extend_from_slice(&(x.len() as u32).to_le_bytes());
    v.extend_from_slice(x);
    v
}

/// `PRK_w`: the one Extract at the wallet root.
pub fn wallet_prk(wallet_seed: &[u8]) -> Prk {
    extract(TAG_DSM_KDF_WALLET_ROOT_V1, wallet_seed)
}

/// `PRK_d`: the Extract under the device seed.
pub fn device_prk(device_seed: &[u8; 32]) -> Prk {
    extract(TAG_DSM_KDF_DEVICE_ROOT_V1, device_seed)
}

/// `PRK_s0`: the Extract under `s0`.
pub fn s0_prk(s0: &[u8; 32]) -> Prk {
    extract(TAG_DSM_KDF_S0_ROOT_V1, s0)
}

/// Public genesis nonce. PUBLIC.
pub fn genesis_nonce(prk_w: &Prk, network_id: &[u8], wallet_index: u32) -> [u8; 32] {
    expand32(
        prk_w,
        TAG_DSM_GENESIS_NONCE_V3,
        &[&lp(network_id), &wallet_index.to_le_bytes()],
    )
}

/// Genesis Root Key seed. No `G` input (see `genesis_v3`).
pub fn grk_seed(
    prk_w: &Prk,
    network_id: &[u8],
    wallet_index: u32,
    genesis_version: u32,
) -> [u8; 32] {
    expand32(
        prk_w,
        TAG_DSM_GENESIS_ROOT_AUTHORITY_V2,
        &[
            &lp(network_id),
            &wallet_index.to_le_bytes(),
            &genesis_version.to_le_bytes(),
        ],
    )
}

/// Device-birth attestation digest. PUBLIC.
pub fn atta(prk_w: &Prk, g: &[u8; 32], device_slot: u32) -> [u8; 32] {
    expand32(prk_w, TAG_DSM_ATTA_V3, &[g, &device_slot.to_le_bytes()])
}

/// Device seed (roots the AK).
pub fn device_seed(prk_w: &Prk, g: &[u8; 32], device_slot: u32) -> [u8; 32] {
    expand32(
        prk_w,
        TAG_DSM_DEVICE_SEED_V3,
        &[g, &device_slot.to_le_bytes()],
    )
}

/// Secret root `s0` (roots Smaster and the at-rest key).
pub fn s0(prk_w: &Prk, g: &[u8; 32], device_slot: u32, aph: &[u8; 32]) -> [u8; 32] {
    expand32(prk_w, TAG_DSM_S0_V3, &[g, &device_slot.to_le_bytes(), aph])
}

/// SDK context entropy.
pub fn sdk_entropy(prk_w: &Prk, devid: &[u8; 32], g: &[u8; 32]) -> [u8; 32] {
    expand32(prk_w, TAG_DSM_SDK_ENTROPY_V3, &[devid, g])
}

/// The recovery ring's AEAD key.
pub fn recovery_aead_key(prk_w: &Prk) -> [u8; 32] {
    expand32(prk_w, TAG_DSM_RECOVERY_AEAD_V2, &[])
}

/// The recovery-authority SPHINCS+ seed (its public key is published).
pub fn recovery_authority_seed(prk_w: &Prk) -> [u8; 32] {
    expand32(prk_w, TAG_DSM_RECOVERY_AUTHORITY_V2, &[])
}

/// AK seed, under the device seed's Extract.
pub fn ak_seed(device_seed: &[u8; 32], aph: &[u8; 32]) -> [u8; 32] {
    expand32(&device_prk(device_seed), TAG_DSM_DEVICE_AK_V3, &[aph])
}

/// `Smaster`, under `s0`'s Extract.
pub fn smaster(s0: &[u8; 32], g: &[u8; 32], devid: &[u8; 32], aph: &[u8; 32]) -> [u8; 32] {
    expand32(&s0_prk(s0), TAG_DSM_SMASTER_V3, &[g, devid, aph])
}

/// The chain-head at-rest AEAD key, under `s0`'s Extract, beside `Smaster`:
/// exposing it does not expose `Smaster`.
pub fn at_rest_key(s0: &[u8; 32], g: &[u8; 32], devid: &[u8; 32]) -> [u8; 32] {
    expand32(&s0_prk(s0), TAG_DSM_CHAIN_HEAD_AT_REST_V3, &[g, devid])
}

/// The ML-KEM identity seed: keyed BLAKE3 under `Smaster`, the same interface
/// as the per-step EK seeds and the encapsulation coins.
pub fn ml_kem_seed(smaster: &[u8; 32]) -> [u8; 32] {
    let mut h = crate::crypto::blake3::dsm_domain_hasher_keyed(TAG_DSM_ML_KEM_IDENTITY_V1, smaster);
    h.update(crate::crypto::ephemeral_key::KYBER_ALG_ID_MLKEM768);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    const SEED: [u8; 64] = [0x5a; 64];
    const NET: &[u8] = b"dsm-beta";
    const G: [u8; 32] = [0x47; 32];
    const DEVID: [u8; 32] = [0x44; 32];
    const APH: [u8; 32] = [0x11; 32];

    /// Every `info` label is distinct and NUL-free, so `info` strings of
    /// different labels never coincide.
    #[test]
    fn labels_are_distinct_and_nul_free() {
        let labels = [
            TAG_DSM_GENESIS_NONCE_V3,
            TAG_DSM_GENESIS_ROOT_AUTHORITY_V2,
            TAG_DSM_ATTA_V3,
            TAG_DSM_DEVICE_SEED_V3,
            TAG_DSM_S0_V3,
            TAG_DSM_SDK_ENTROPY_V3,
            TAG_DSM_RECOVERY_AEAD_V2,
            TAG_DSM_RECOVERY_AUTHORITY_V2,
            TAG_DSM_DEVICE_AK_V3,
            TAG_DSM_SMASTER_V3,
            TAG_DSM_CHAIN_HEAD_AT_REST_V3,
        ];
        for (i, a) in labels.iter().enumerate() {
            assert!(!a.source_bytes().contains(&0u8));
            for b in labels.iter().skip(i + 1) {
                assert_ne!(a.source_bytes(), b.source_bytes());
            }
        }
        let salts = [
            TAG_DSM_KDF_WALLET_ROOT_V1,
            TAG_DSM_KDF_DEVICE_ROOT_V1,
            TAG_DSM_KDF_S0_ROOT_V1,
        ];
        for (i, a) in salts.iter().enumerate() {
            for b in salts.iter().skip(i + 1) {
                assert_ne!(a.source_bytes(), b.source_bytes());
            }
        }
    }

    /// The at-rest key and Smaster are Expands of the same PRK at distinct `info`
    /// strings, and neither is `s0`: exposing the at-rest key exposes one PRF output at
    /// another input, not the PRK, `s0` or Smaster (the formal statement is Lean
    /// `snode_info_inj` plus the PRF security of HMAC-BLAKE3 under `PRK_s0`).
    #[test]
    fn the_at_rest_key_is_a_sibling_of_smaster() {
        let w = wallet_prk(&SEED);
        let s = s0(&w, &G, 0, &APH);
        let k = at_rest_key(&s, &G, &DEVID);
        let m = smaster(&s, &G, &DEVID, &APH);
        assert_ne!(k, m);
        assert_ne!(k, s);
        assert_ne!(m, s);
        assert_ne!(
            info(TAG_DSM_CHAIN_HEAD_AT_REST_V3, &[&G, &DEVID]),
            info(TAG_DSM_SMASTER_V3, &[&G, &DEVID, &APH])
        );
    }

    /// The variable-width network id is length-prefixed: moving bytes between
    /// it and the wallet index changes `info`.
    #[test]
    fn network_id_is_length_prefixed() {
        let a = info(TAG_DSM_GENESIS_NONCE_V3, &[&lp(b"ab"), &1u32.to_le_bytes()]);
        let b = info(TAG_DSM_GENESIS_NONCE_V3, &[&lp(b"a"), &[b'b', 1, 0, 0]]);
        assert_ne!(a, b);
    }

    /// Deterministic test vectors for every node of KS1, computed by the independent
    /// reference implementation `scripts/ks1_reference.py` (wallet seed `0x5a`*64,
    /// network `dsm-beta`, index 0, version 3, slot 0, `G` = `0x47`*32,
    /// `DevID` = `0x44`*32, `aph` = `0x11`*32). Changing any of them changes
    /// every identity: bump the schedule, never edit a vector to match.
    #[test]
    fn ks1_test_vectors() {
        let w = wallet_prk(&SEED);
        let ds = device_seed(&w, &G, 0);
        let s = s0(&w, &G, 0, &APH);
        let sm = smaster(&s, &G, &DEVID, &APH);
        let got = [
            ("genesis_nonce", hex(&genesis_nonce(&w, NET, 0))),
            ("grk_seed", hex(&grk_seed(&w, NET, 0, 3))),
            ("atta", hex(&atta(&w, &G, 0))),
            ("device_seed", hex(&ds)),
            ("s0", hex(&s)),
            ("sdk_entropy", hex(&sdk_entropy(&w, &DEVID, &G))),
            ("recovery_aead_key", hex(&recovery_aead_key(&w))),
            ("recovery_authority_seed", hex(&recovery_authority_seed(&w))),
            ("ak_seed", hex(&ak_seed(&ds, &APH))),
            ("smaster", hex(&sm)),
            ("at_rest_key", hex(&at_rest_key(&s, &G, &DEVID))),
            ("ml_kem_seed", hex(&ml_kem_seed(&sm))),
        ];
        let want: [(&str, &str); 12] = KS1_VECTORS;
        for ((n, g), (wn, wv)) in got.iter().zip(want.iter()) {
            assert_eq!(n, wn);
            assert_eq!(g, wv, "KS1 vector {n}");
        }
    }

    const KS1_VECTORS: [(&str, &str); 12] = [
        (
            "genesis_nonce",
            "5e76000aee25c41c1a01de1a46837ae66eab039bfb056a57073a0cd25f859768",
        ),
        (
            "grk_seed",
            "04b8c98b3cc835aa76591c2fc10e1c8e9c66d13da8efac2f528de9c761147cb3",
        ),
        (
            "atta",
            "d10e83a47261119e4ceb822453e0fed6ddfe591f5b3f8be00f396ff049644291",
        ),
        (
            "device_seed",
            "654337f2220f7ff73796e055d28ddceb6981c599c6ed8127f8ea3a1685907214",
        ),
        (
            "s0",
            "47e318c588b79ed838e1d3b681ef66b02be4dc111bc76389a9557162e66f6604",
        ),
        (
            "sdk_entropy",
            "589a5ca28f0c1c2e0b449cb8a3b98754b4c471134f1239e4868c49ecf7ead699",
        ),
        (
            "recovery_aead_key",
            "1c1d49043341b1766e74183280bf8c578854158ca627269275d0fe5ee702e28c",
        ),
        (
            "recovery_authority_seed",
            "6f50a86a1bc8782d4460bdf2085a222873f274e304863610cff0b34322396eff",
        ),
        (
            "ak_seed",
            "3e12319bfccf9bbc9b028ffd60b7c2a51ea1d7eec63e4bdb23252d61a047c3c0",
        ),
        (
            "smaster",
            "f35c38410205174d7170802c5573826f187febc46dd1f4932a3192a127487386",
        ),
        (
            "at_rest_key",
            "3ba00d357efaf61ddab37275c46b8cb64a334e0a6a9f8d751c23e313f0b54b37",
        ),
        (
            "ml_kem_seed",
            "978325675bbfaee26c23901f843b9bb03ab281f4fc50ed24a287fb5c78ebed0f",
        ),
    ];
}
