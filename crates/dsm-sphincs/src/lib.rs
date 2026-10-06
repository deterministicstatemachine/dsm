// SPDX-License-Identifier: MIT OR Apache-2.0

//! SPHINCS+ for DSM: the FIPS 205 (SLH-DSA) structure, instantiated with BLAKE3.
//!
//! This crate is the one SPHINCS+ implementation in DSM. The host
//! (`dsm::crypto::sphincs`) and the RP2350 anchor firmware both link it, so a
//! signature produced by either verifies under the other by construction.
//!
//! # Structure (construction version 2)
//!
//! Every algorithm follows FIPS 205 §5–§10: WOTS+ (`wots_pkgen`, `wots_sign`,
//! `wots_pk_from_sig`, with the public key compressed by `T_len` under its own
//! `WOTS_PK` address), XMSS (`xmss_node`, `xmss_sign`, `xmss_pk_from_sig`), the
//! hypertree (`ht_sign`, `ht_verify`) and FORS (`fors_sk_gen`, `fors_node`,
//! `fors_sign`, `fors_pk_from_sig`). The address is the FIPS 205 32-byte ADRS:
//!
//! ```text
//! word 0      layer
//! words 1..3  tree (96 bits; DSM trees fit in the low 64)
//! word 4      type   0 WOTS_HASH, 1 WOTS_PK, 2 TREE, 3 FORS_TREE,
//!                    4 FORS_ROOTS, 5 WOTS_PRF, 6 FORS_PRF
//! word 5      key pair            (WOTS_*, FORS_*)
//! word 6      chain | tree height (WOTS_HASH, WOTS_PRF | TREE, FORS_*)
//! word 7      hash  | tree index  (WOTS_HASH | TREE, FORS_TREE, FORS_PRF)
//! ```
//!
//! Changing the type clears words 5–7 (`setTypeAndClear`). Every hash call in
//! a key generation, a signature or a verification therefore has its own
//! address: a FORS key belongs to the hypertree leaf that signs it (key pair =
//! leaf index, tree index = `i·2^a + j`), secret values are drawn under their
//! own PRF types, tree heights count from the leaves, and WOTS+ public-key
//! compression is not a hashtree node. The unit tests record every call and
//! hold each of these.
//!
//! # BLAKE3 instantiation
//!
//! This is not FIPS 205: the hash family is BLAKE3, not SHAKE or SHA-2, so no
//! FIPS 205 test vector applies. The structure gives a SPHINCS+-style proof
//! the separation it assumes; the instantiation itself awaits an independent
//! cryptographic review.
//!
//! ```text
//! PRF(PK.seed, SK.seed, ADRS)  = BLAKE3-keyed(derive_key(PRF ctx, SK.seed), PK.seed ‖ ADRS)[..n]
//! F / H / T_l(PK.seed, ADRS, M) = BLAKE3-keyed(derive_key(THASH ctx, PK.seed), ADRS ‖ M)[..n]
//! PRF_msg(SK.prf, opt_rand, M) = BLAKE3-keyed(derive_key(PRF_MSG ctx, SK.prf), opt_rand ‖ M)[..n]
//! H_msg(R, PK.seed, PK.root, M) = BLAKE3-derive-key-mode(H_MSG ctx; R ‖ PK.seed ‖ PK.root ‖ M), m bytes (XOF)
//! ```
//!
//! Signing is deterministic (FIPS 205 §10.2.1 with `opt_rand = PK.seed`), and
//! a signature is verified before it is returned, so a fault during signing
//! never releases a signature over a corrupted hypertree. An empty message is
//! refused. There is no FIPS 205 context string: DSM signs its own
//! domain-separated digests.
//!
//! Keys are `pk = PK.seed ‖ PK.root` (2n bytes) and
//! `sk = SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` (4n bytes). Key generation from
//! a 32-byte seed expands it with ChaCha20 into `SK.seed ‖ SK.prf ‖ PK.seed`.

#![cfg_attr(not(test), no_std)]
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// no_std error type for this crate (replaces the host `DsmError`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A cryptographic precondition failed (bad sizes, empty message, etc.).
    Crypto(&'static str),
}

/// The version of the construction: the address layout and the BLAKE3
/// instantiation above. Version 1, retired, gave every leaf of a bottom tree
/// one FORS key and shared addresses between unrelated hash calls.
pub const CONSTRUCTION_VERSION: u16 = 2;

// ========================== Parameters & Sizes ===============================

#[derive(Clone, Copy, Debug, Eq, PartialEq, Zeroize)]
pub enum SphincsVariant {
    SPX128s,
    SPX128f,
    SPX192s,
    SPX192f,
    SPX256s,
    SPX256f,
}

/// `lg_w`: WOTS+ digits are base 16.
const LG_W: usize = 4;
const W: u32 = 16;

#[derive(Clone, Copy, Debug)]
struct Params {
    n: usize,
    h: usize,
    d: usize,
    /// `h'`, the height of one XMSS tree.
    hp: usize,
    a: usize,
    k: usize,
    len1: usize,
    len2: usize,
    len: usize,
    /// `ceil(k·a / 8)`: the FORS message digest.
    md_bytes: usize,
    /// `ceil((h − h') / 8)`: the tree index.
    tree_bytes: usize,
    /// `ceil(h' / 8)`: the leaf index.
    leaf_bytes: usize,
    /// `m`, the length of `H_msg`'s output.
    m: usize,
    pk_bytes: usize,
    sk_bytes: usize,
    sig_bytes: usize,
}

/// `len2 = floor(log_w(len1·(w − 1))) + 1`: the number of base-`w` digits of
/// the largest checksum, computed in integers (no `f64` in no_std).
fn compute_wots_len2(len1: usize) -> usize {
    let max_checksum = (len1 * (W as usize - 1)) as u64;
    let mut len2 = 0usize;
    let mut p: u64 = 1;
    while p <= max_checksum {
        p *= u64::from(W);
        len2 += 1;
    }
    len2
}

fn param_set(v: SphincsVariant) -> Params {
    // FIPS 205 Table 2.
    let (n, h, d, a, k): (usize, usize, usize, usize, usize) = match v {
        SphincsVariant::SPX128s => (16, 63, 7, 12, 14),
        SphincsVariant::SPX128f => (16, 66, 22, 6, 33),
        SphincsVariant::SPX192s => (24, 63, 7, 14, 17),
        SphincsVariant::SPX192f => (24, 66, 22, 8, 33),
        SphincsVariant::SPX256s => (32, 64, 8, 14, 22),
        SphincsVariant::SPX256f => (32, 68, 17, 9, 35),
    };
    let hp = h / d;
    let len1 = 8 * n / LG_W;
    let len2 = compute_wots_len2(len1);
    let len = len1 + len2;
    let md_bytes = (k * a).div_ceil(8);
    let tree_bytes = (h - hp).div_ceil(8);
    let leaf_bytes = hp.div_ceil(8);
    Params {
        n,
        h,
        d,
        hp,
        a,
        k,
        len1,
        len2,
        len,
        md_bytes,
        tree_bytes,
        leaf_bytes,
        m: md_bytes + tree_bytes + leaf_bytes,
        pk_bytes: 2 * n,
        sk_bytes: 4 * n,
        sig_bytes: n + k * (a + 1) * n + (h + d * len) * n,
    }
}

pub fn sizes(v: SphincsVariant) -> (usize, usize, usize) {
    let p = param_set(v);
    (p.pk_bytes, p.sk_bytes, p.sig_bytes)
}

// =============================== Address ====================================

const WOTS_HASH: u32 = 0;
const WOTS_PK: u32 = 1;
const TREE: u32 = 2;
const FORS_TREE: u32 = 3;
const FORS_ROOTS: u32 = 4;
const WOTS_PRF: u32 = 5;
const FORS_PRF: u32 = 6;

/// The FIPS 205 ADRS as eight big-endian words (layout in the crate docs).
#[derive(Clone, Copy, Debug)]
struct Adrs {
    w: [u32; 8],
}

impl Adrs {
    fn new() -> Self {
        Self { w: [0; 8] }
    }
    fn set_layer(&mut self, layer: u32) {
        self.w[0] = layer;
    }
    fn set_tree(&mut self, tree: u64) {
        self.w[1] = 0;
        self.w[2] = (tree >> 32) as u32;
        self.w[3] = tree as u32;
    }
    /// `setTypeAndClear`: the type, with every type-specific word cleared.
    fn set_type_and_clear(&mut self, t: u32) {
        self.w[4] = t;
        self.w[5] = 0;
        self.w[6] = 0;
        self.w[7] = 0;
    }
    fn set_keypair(&mut self, keypair: u32) {
        self.w[5] = keypair;
    }
    fn keypair(&self) -> u32 {
        self.w[5]
    }
    fn set_chain(&mut self, chain: u32) {
        self.w[6] = chain;
    }
    fn set_tree_height(&mut self, z: u32) {
        self.w[6] = z;
    }
    fn set_hash(&mut self, j: u32) {
        self.w[7] = j;
    }
    fn set_tree_index(&mut self, i: u32) {
        self.w[7] = i;
    }
    fn tree_index(&self) -> u32 {
        self.w[7]
    }
    fn as_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, word) in self.w.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod refinement_vectors;

fn derive_key(context: &str, input: &[u8]) -> [u8; 32] {
    let output = blake3::derive_key(context, input);
    #[cfg(test)]
    refinement_vectors::record(0, context, &[], input, &output);
    output
}

// =============================== Hash/PRF ===================================

/// BLAKE3 KDF contexts, one per role. Each is fixed and unique to that role.
const CONTEXT_PRF: &str = "DSM/sphincs/v2/prf";
const CONTEXT_THASH: &str = "DSM/sphincs/v2/thash";
const CONTEXT_PRF_MSG: &str = "DSM/sphincs/v2/prf-msg";
const CONTEXT_H_MSG: &str = "DSM/sphincs/v2/h-msg";

/// What every hash call of one key needs: `n`, `PK.seed` and the tweakable
/// hash's key, derived once from `PK.seed`.
struct PublicCtx {
    n: usize,
    pk_seed: Vec<u8>,
    thash_key: [u8; 32],
}

impl PublicCtx {
    fn new(n: usize, pk_seed: &[u8]) -> Self {
        Self {
            n,
            pk_seed: pk_seed.to_vec(),
            thash_key: derive_key(CONTEXT_THASH, pk_seed),
        }
    }
}

/// The PRF's key, derived once from `SK.seed`, cleared on drop.
struct SecretCtx {
    prf_key: Zeroizing<[u8; 32]>,
}

impl SecretCtx {
    fn new(sk_seed: &[u8]) -> Self {
        Self {
            prf_key: Zeroizing::new(derive_key(CONTEXT_PRF, sk_seed)),
        }
    }
}

fn keyed(n: usize, key: &[u8; 32], inputs: &[&[u8]]) -> Vec<u8> {
    let mut h = Zeroizing::new(blake3::Hasher::new_keyed(key));
    for input in inputs {
        h.update(input);
    }
    let mut out = vec![0u8; n];
    let digest = Zeroizing::new(h.finalize());
    out.copy_from_slice(&digest.as_bytes()[..n]);
    #[cfg(test)]
    refinement_vectors::record(1, "", key, &inputs.concat(), &out);
    out
}

/// `F`, `H` and `T_l`: the tweakable hash over `ADRS ‖ M`.
fn thash(pc: &PublicCtx, adrs: &Adrs, inputs: &[&[u8]]) -> Vec<u8> {
    let a = adrs.as_bytes();
    #[cfg(test)]
    trace::record(&a, trace::ROLE_THASH, inputs);
    let mut pieces: Vec<&[u8]> = Vec::with_capacity(1 + inputs.len());
    pieces.push(&a);
    pieces.extend_from_slice(inputs);
    keyed(pc.n, &pc.thash_key, &pieces)
}

/// `PRF(PK.seed, SK.seed, ADRS)`: a secret value, cleared on drop.
fn prf(pc: &PublicCtx, sc: &SecretCtx, adrs: &Adrs) -> Zeroizing<Vec<u8>> {
    let a = adrs.as_bytes();
    #[cfg(test)]
    trace::record(&a, trace::ROLE_PRF, &[]);
    Zeroizing::new(keyed(pc.n, &sc.prf_key, &[&pc.pk_seed, &a]))
}

/// `PRF_msg(SK.prf, opt_rand, M)`: the randomizer `R`.
fn prf_msg(n: usize, sk_prf: &[u8], opt_rand: &[u8], m: &[u8]) -> Vec<u8> {
    let key = Zeroizing::new(derive_key(CONTEXT_PRF_MSG, sk_prf));
    keyed(n, &key, &[opt_rand, m])
}

/// `H_msg(R, PK.seed, PK.root, M)`: `m` bytes.
fn h_msg(p: &Params, r: &[u8], pk_seed: &[u8], pk_root: &[u8], m: &[u8]) -> Vec<u8> {
    let mut h = blake3::Hasher::new_derive_key(CONTEXT_H_MSG);
    h.update(r);
    h.update(pk_seed);
    h.update(pk_root);
    h.update(m);
    let mut out = vec![0u8; p.m];
    h.finalize_xof().fill(&mut out);
    #[cfg(test)]
    refinement_vectors::record(
        2,
        CONTEXT_H_MSG,
        &[],
        &[r, pk_seed, pk_root, m].concat(),
        &out,
    );
    out
}

// ============================ Encoding helpers ==============================

/// FIPS 205 Algorithm 4, `base_2b`: `out_len` integers of `b` bits each,
/// most significant first. `x` holds at least `ceil(out_len·b / 8)` bytes.
fn base_2b(x: &[u8], b: usize, out_len: usize) -> Vec<u32> {
    let mut input = 0usize;
    let mut bits = 0usize;
    let mut total: u64 = 0;
    let mask = (1u64 << b) - 1;
    let mut out = Vec::with_capacity(out_len);
    for _ in 0..out_len {
        while bits < b {
            total = (total << 8) | u64::from(x[input]);
            input += 1;
            bits += 8;
        }
        bits -= b;
        out.push(((total >> bits) & mask) as u32);
        total &= (1u64 << bits) - 1;
    }
    out
}

/// FIPS 205 Algorithm 2, `toInt`, over at most 8 bytes.
fn to_int(x: &[u8]) -> u64 {
    x.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
}

/// FIPS 205 Algorithm 3, `toByte`: the low `len` bytes of `x`, big-endian.
fn to_byte(x: u64, len: usize) -> Vec<u8> {
    x.to_be_bytes()[8 - len..].to_vec()
}

/// The `len` base-`w` digits WOTS+ signs: the message's `len1` and the
/// checksum's `len2` (FIPS 205 Algorithm 7, lines 1–9).
fn wots_digits(p: &Params, m: &[u8]) -> Vec<u32> {
    let mut digits = base_2b(m, LG_W, p.len1);
    let csum: u32 = digits.iter().map(|d| (W - 1) - d).sum();
    let shift = (8 - ((p.len2 * LG_W) % 8)) % 8;
    let csum_bytes = to_byte(u64::from(csum) << shift, (p.len2 * LG_W).div_ceil(8));
    digits.extend(base_2b(&csum_bytes, LG_W, p.len2));
    digits
}

// ================================ WOTS+ =====================================

/// FIPS 205 Algorithm 5, `chain`: `s` steps from step `i`.
fn chain(pc: &PublicCtx, x: &[u8], i: u32, s: u32, adrs: &mut Adrs) -> Vec<u8> {
    // Intermediate chains can contain unreleased secret-derived values.
    // Clear each replaced allocation and the final working copy on drop.
    let mut tmp = Zeroizing::new(x.to_vec());
    for j in i..i + s {
        adrs.set_hash(j);
        tmp = Zeroizing::new(thash(pc, adrs, &[&tmp]));
    }
    tmp.to_vec()
}

/// The address a WOTS+ secret value is drawn under.
fn wots_sk_adrs(adrs: &Adrs) -> Adrs {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(WOTS_PRF);
    sk_adrs.set_keypair(adrs.keypair());
    sk_adrs
}

/// `T_len` under the key pair's own `WOTS_PK` address.
fn wots_compress(pc: &PublicCtx, adrs: &Adrs, tops: &[u8]) -> Vec<u8> {
    let mut pk_adrs = *adrs;
    pk_adrs.set_type_and_clear(WOTS_PK);
    pk_adrs.set_keypair(adrs.keypair());
    thash(pc, &pk_adrs, &[tops])
}

/// FIPS 205 Algorithm 6, `wots_pkGen`. `adrs` is a `WOTS_HASH` address with
/// its key pair set.
fn wots_pkgen(p: &Params, pc: &PublicCtx, sc: &SecretCtx, adrs: &Adrs) -> Vec<u8> {
    let mut sk_adrs = wots_sk_adrs(adrs);
    let mut chain_adrs = *adrs;
    let mut tops = Vec::with_capacity(p.len * p.n);
    for i in 0..p.len as u32 {
        sk_adrs.set_chain(i);
        let sk = prf(pc, sc, &sk_adrs);
        chain_adrs.set_chain(i);
        tops.extend(chain(pc, &sk, 0, W - 1, &mut chain_adrs));
    }
    wots_compress(pc, adrs, &tops)
}

/// FIPS 205 Algorithm 7, `wots_sign`.
fn wots_sign(p: &Params, pc: &PublicCtx, sc: &SecretCtx, m: &[u8], adrs: &Adrs) -> Vec<u8> {
    let mut sk_adrs = wots_sk_adrs(adrs);
    let mut chain_adrs = *adrs;
    let mut sig = Vec::with_capacity(p.len * p.n);
    for (i, digit) in wots_digits(p, m).into_iter().enumerate() {
        sk_adrs.set_chain(i as u32);
        let sk = prf(pc, sc, &sk_adrs);
        chain_adrs.set_chain(i as u32);
        sig.extend(chain(pc, &sk, 0, digit, &mut chain_adrs));
    }
    sig
}

/// FIPS 205 Algorithm 8, `wots_pkFromSig`.
fn wots_pk_from_sig(p: &Params, pc: &PublicCtx, sig: &[u8], m: &[u8], adrs: &Adrs) -> Vec<u8> {
    let mut chain_adrs = *adrs;
    let mut tops = Vec::with_capacity(p.len * p.n);
    for (i, digit) in wots_digits(p, m).into_iter().enumerate() {
        chain_adrs.set_chain(i as u32);
        tops.extend(chain(
            pc,
            &sig[i * p.n..(i + 1) * p.n],
            digit,
            W - 1 - digit,
            &mut chain_adrs,
        ));
    }
    wots_compress(pc, adrs, &tops)
}

// ================================ XMSS ======================================

/// FIPS 205 Algorithm 9, `xmss_node`: the node at height `z`, index `i`.
fn xmss_node(
    p: &Params,
    pc: &PublicCtx,
    sc: &SecretCtx,
    i: u32,
    z: u32,
    adrs: &mut Adrs,
) -> Vec<u8> {
    if z == 0 {
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_keypair(i);
        return wots_pkgen(p, pc, sc, adrs);
    }
    let left = xmss_node(p, pc, sc, 2 * i, z - 1, adrs);
    let right = xmss_node(p, pc, sc, 2 * i + 1, z - 1, adrs);
    adrs.set_type_and_clear(TREE);
    adrs.set_tree_height(z);
    adrs.set_tree_index(i);
    thash(pc, adrs, &[&left, &right])
}

/// FIPS 205 Algorithm 10, `xmss_sign`: the WOTS+ signature, then the
/// authentication path.
fn xmss_sign(
    p: &Params,
    pc: &PublicCtx,
    sc: &SecretCtx,
    m: &[u8],
    idx: u32,
    adrs: &mut Adrs,
) -> Vec<u8> {
    let mut auth = Vec::with_capacity(p.hp * p.n);
    for j in 0..p.hp as u32 {
        let sibling = (idx >> j) ^ 1;
        auth.extend(xmss_node(p, pc, sc, sibling, j, adrs));
    }
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_keypair(idx);
    let mut sig = wots_sign(p, pc, sc, m, adrs);
    sig.extend(auth);
    sig
}

/// FIPS 205 Algorithm 11, `xmss_pkFromSig`.
fn xmss_pk_from_sig(
    p: &Params,
    pc: &PublicCtx,
    idx: u32,
    sig: &[u8],
    m: &[u8],
    adrs: &mut Adrs,
) -> Vec<u8> {
    let (wots, auth) = sig.split_at(p.len * p.n);
    adrs.set_type_and_clear(WOTS_HASH);
    adrs.set_keypair(idx);
    let mut node = wots_pk_from_sig(p, pc, wots, m, adrs);
    adrs.set_type_and_clear(TREE);
    adrs.set_tree_index(idx);
    for k in 0..p.hp {
        let sibling = &auth[k * p.n..(k + 1) * p.n];
        adrs.set_tree_height(k as u32 + 1);
        if (idx >> k).is_multiple_of(2) {
            adrs.set_tree_index(adrs.tree_index() / 2);
            node = thash(pc, adrs, &[&node, sibling]);
        } else {
            adrs.set_tree_index((adrs.tree_index() - 1) / 2);
            node = thash(pc, adrs, &[sibling, &node]);
        }
    }
    node
}

// ============================== Hypertree ===================================

/// The leaf index into the next layer's tree, and that tree's index.
fn next_layer(p: &Params, tree: u64) -> (u32, u64) {
    ((tree & ((1u64 << p.hp) - 1)) as u32, tree >> p.hp)
}

/// FIPS 205 Algorithm 12, `ht_sign`.
fn ht_sign(
    p: &Params,
    pc: &PublicCtx,
    sc: &SecretCtx,
    m: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
) -> Vec<u8> {
    let mut adrs = Adrs::new();
    adrs.set_tree(idx_tree);
    let mut sig = xmss_sign(p, pc, sc, m, idx_leaf, &mut adrs);
    let mut root = xmss_pk_from_sig(p, pc, idx_leaf, &sig, m, &mut adrs);
    let mut tree = idx_tree;
    for j in 1..p.d {
        let (leaf, next) = next_layer(p, tree);
        tree = next;
        adrs.set_layer(j as u32);
        adrs.set_tree(tree);
        let layer_sig = xmss_sign(p, pc, sc, &root, leaf, &mut adrs);
        if j < p.d - 1 {
            root = xmss_pk_from_sig(p, pc, leaf, &layer_sig, &root, &mut adrs);
        }
        sig.extend(layer_sig);
    }
    sig
}

/// FIPS 205 Algorithm 13, `ht_verify`.
fn ht_verify(
    p: &Params,
    pc: &PublicCtx,
    m: &[u8],
    sig: &[u8],
    idx_tree: u64,
    idx_leaf: u32,
    pk_root: &[u8],
) -> bool {
    let layer_bytes = (p.len + p.hp) * p.n;
    let mut adrs = Adrs::new();
    adrs.set_tree(idx_tree);
    let mut node = xmss_pk_from_sig(p, pc, idx_leaf, &sig[..layer_bytes], m, &mut adrs);
    let mut tree = idx_tree;
    for j in 1..p.d {
        let (leaf, next) = next_layer(p, tree);
        tree = next;
        adrs.set_layer(j as u32);
        adrs.set_tree(tree);
        node = xmss_pk_from_sig(
            p,
            pc,
            leaf,
            &sig[j * layer_bytes..(j + 1) * layer_bytes],
            &node,
            &mut adrs,
        );
    }
    node.ct_eq(pk_root).unwrap_u8() == 1
}

// ================================ FORS ======================================

/// FIPS 205 Algorithm 14, `fors_skGen`: secret leaf `idx` of the FORS key
/// `adrs` names (its key pair is the hypertree leaf that signs it).
fn fors_sk_gen(pc: &PublicCtx, sc: &SecretCtx, adrs: &Adrs, idx: u32) -> Zeroizing<Vec<u8>> {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(FORS_PRF);
    sk_adrs.set_keypair(adrs.keypair());
    sk_adrs.set_tree_index(idx);
    prf(pc, sc, &sk_adrs)
}

/// FIPS 205 Algorithm 15, `fors_node`: the node at height `z`, index `i`,
/// counted across all `k` trees.
fn fors_node(pc: &PublicCtx, sc: &SecretCtx, i: u32, z: u32, adrs: &mut Adrs) -> Vec<u8> {
    if z == 0 {
        let sk = fors_sk_gen(pc, sc, adrs, i);
        adrs.set_tree_height(0);
        adrs.set_tree_index(i);
        return thash(pc, adrs, &[&sk]);
    }
    let left = fors_node(pc, sc, 2 * i, z - 1, adrs);
    let right = fors_node(pc, sc, 2 * i + 1, z - 1, adrs);
    adrs.set_tree_height(z);
    adrs.set_tree_index(i);
    thash(pc, adrs, &[&left, &right])
}

/// FIPS 205 Algorithm 16, `fors_sign`.
fn fors_sign(p: &Params, pc: &PublicCtx, sc: &SecretCtx, md: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    let mut sig = Vec::with_capacity(p.k * (p.a + 1) * p.n);
    for (i, idx) in base_2b(md, p.a, p.k).into_iter().enumerate() {
        let tree = i as u32;
        sig.extend_from_slice(&fors_sk_gen(pc, sc, adrs, (tree << p.a) + idx));
        for j in 0..p.a {
            let sibling = (idx >> j) ^ 1;
            sig.extend(fors_node(
                pc,
                sc,
                (tree << (p.a - j)) + sibling,
                j as u32,
                adrs,
            ));
        }
    }
    sig
}

/// FIPS 205 Algorithm 17, `fors_pkFromSig`.
fn fors_pk_from_sig(p: &Params, pc: &PublicCtx, sig: &[u8], md: &[u8], adrs: &mut Adrs) -> Vec<u8> {
    let step = (p.a + 1) * p.n;
    let mut roots = Vec::with_capacity(p.k * p.n);
    for (i, idx) in base_2b(md, p.a, p.k).into_iter().enumerate() {
        let (sk, auth) = sig[i * step..(i + 1) * step].split_at(p.n);
        adrs.set_tree_height(0);
        adrs.set_tree_index(((i as u32) << p.a) + idx);
        let mut node = thash(pc, adrs, &[sk]);
        for j in 0..p.a {
            let sibling = &auth[j * p.n..(j + 1) * p.n];
            adrs.set_tree_height(j as u32 + 1);
            if (idx >> j).is_multiple_of(2) {
                adrs.set_tree_index(adrs.tree_index() / 2);
                node = thash(pc, adrs, &[&node, sibling]);
            } else {
                adrs.set_tree_index((adrs.tree_index() - 1) / 2);
                node = thash(pc, adrs, &[sibling, &node]);
            }
        }
        roots.extend(node);
    }
    let mut roots_adrs = *adrs;
    roots_adrs.set_type_and_clear(FORS_ROOTS);
    roots_adrs.set_keypair(adrs.keypair());
    thash(pc, &roots_adrs, &[&roots])
}

// =============================== Digest =====================================

/// `H_msg`'s output split as FIPS 205 Algorithm 19 lines 6–10 split it.
struct Indices {
    md: Vec<u8>,
    idx_tree: u64,
    idx_leaf: u32,
}

fn split_digest(p: &Params, digest: &[u8]) -> Indices {
    let (md, rest) = digest.split_at(p.md_bytes);
    let (tree, rest) = rest.split_at(p.tree_bytes);
    let leaf = &rest[..p.leaf_bytes];
    let tree_bits = (p.h - p.hp) as u32;
    let tree_mask = 1u64
        .checked_shl(tree_bits)
        .map_or(u64::MAX, |bound| bound - 1);
    Indices {
        md: md.to_vec(),
        idx_tree: to_int(tree) & tree_mask,
        idx_leaf: (to_int(leaf) & ((1u64 << p.hp) - 1)) as u32,
    }
}

/// The FORS address of the key that signs at `(idx_tree, idx_leaf)`.
fn fors_adrs(at: &Indices) -> Adrs {
    let mut adrs = Adrs::new();
    adrs.set_tree(at.idx_tree);
    adrs.set_type_and_clear(FORS_TREE);
    adrs.set_keypair(at.idx_leaf);
    adrs
}

// =============================== Key Material ===============================

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SphincsKeyPair {
    pub public_key: Vec<u8>, // PK.seed || PK.root
    pub secret_key: Vec<u8>, // SK.seed || SK.prf || PK.seed || PK.root
}

// Diagnostic formatting must never disclose the caller's signing seeds.
impl core::fmt::Debug for SphincsKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SphincsKeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// FIPS 205 Algorithm 18, `slh_keygen_internal`, from seeds ChaCha20 draws
/// from `seed32`.
pub fn generate_keypair_from_seed(
    v: SphincsVariant,
    seed32: &[u8; 32],
) -> Result<SphincsKeyPair, Error> {
    let p = param_set(v);
    let mut sk = Zeroizing::new(vec![0u8; p.sk_bytes]);
    let mut rng = ChaCha20Rng::from_seed(*seed32);
    rng.fill_bytes(&mut sk[..3 * p.n]);
    #[cfg(test)]
    refinement_vectors::record(3, "ChaCha20Rng", &[], seed32, &sk[..3 * p.n]);
    let (sk_seed, rest) = sk.split_at(p.n);
    let pk_seed = &rest[p.n..2 * p.n];
    let pc = PublicCtx::new(p.n, pk_seed);
    let sc = SecretCtx::new(sk_seed);
    let mut adrs = Adrs::new();
    adrs.set_layer((p.d - 1) as u32);
    let root = xmss_node(&p, &pc, &sc, 0, p.hp as u32, &mut adrs);
    let mut pk = Vec::with_capacity(p.pk_bytes);
    pk.extend_from_slice(pk_seed);
    pk.extend_from_slice(&root);
    sk[3 * p.n..].copy_from_slice(&root);
    Ok(SphincsKeyPair {
        public_key: pk,
        secret_key: sk.to_vec(),
    })
}

// =============================== Sign/Verify ================================

/// FIPS 205 Algorithm 19, `slh_sign_internal`, deterministic
/// (`opt_rand = PK.seed`). Layout:
///
/// ```text
/// sig = R (n) ‖ SIG_FORS (k·(a+1)·n) ‖ SIG_HT (d·(len + h')·n)
/// ```
///
/// The signature is verified before it is returned.
pub fn sign(
    v: SphincsVariant,
    sk: &[u8], // SK.seed || SK.prf || PK.seed || PK.root
    m: &[u8],
) -> Result<Vec<u8>, Error> {
    if m.is_empty() {
        return Err(Error::Crypto("Cannot sign empty message"));
    }
    let p = param_set(v);
    if sk.len() != p.sk_bytes {
        return Err(Error::Crypto("Bad secret key size"));
    }
    let (sk_seed, rest) = sk.split_at(p.n);
    let (sk_prf, public) = rest.split_at(p.n);
    let (pk_seed, pk_root) = public.split_at(p.n);
    let pc = PublicCtx::new(p.n, pk_seed);
    let sc = SecretCtx::new(sk_seed);

    let r = prf_msg(p.n, sk_prf, pk_seed, m);
    let at = split_digest(&p, &h_msg(&p, &r, pk_seed, pk_root, m));
    let mut adrs = fors_adrs(&at);
    let fors_sig = fors_sign(&p, &pc, &sc, &at.md, &mut adrs);
    let fors_pk = fors_pk_from_sig(&p, &pc, &fors_sig, &at.md, &mut adrs);
    let ht_sig = ht_sign(&p, &pc, &sc, &fors_pk, at.idx_tree, at.idx_leaf);

    let mut sig = Vec::with_capacity(p.sig_bytes);
    sig.extend(r);
    sig.extend(fors_sig);
    sig.extend(ht_sig);
    if !ht_verify(
        &p,
        &pc,
        &fors_pk,
        &sig[p.n + p.k * (p.a + 1) * p.n..],
        at.idx_tree,
        at.idx_leaf,
        pk_root,
    ) {
        return Err(Error::Crypto(
            "the signature does not verify under its own key: a fault during signing, or a secret \
             key whose root is not its own",
        ));
    }
    Ok(sig)
}

/// FIPS 205 Algorithm 20, `slh_verify_internal`. A key or signature of the
/// wrong length for `v` does not verify.
pub fn verify(
    v: SphincsVariant,
    pk: &[u8], // PK.seed || PK.root
    m: &[u8],
    sig: &[u8],
) -> Result<bool, Error> {
    if m.is_empty() {
        return Err(Error::Crypto("Cannot verify empty message"));
    }
    let p = param_set(v);
    if pk.len() != p.pk_bytes || sig.len() != p.sig_bytes {
        return Ok(false);
    }
    let (pk_seed, pk_root) = pk.split_at(p.n);
    let pc = PublicCtx::new(p.n, pk_seed);
    let (r, rest) = sig.split_at(p.n);
    let (fors_sig, ht_sig) = rest.split_at(p.k * (p.a + 1) * p.n);
    let at = split_digest(&p, &h_msg(&p, r, pk_seed, pk_root, m));
    let mut adrs = fors_adrs(&at);
    let fors_pk = fors_pk_from_sig(&p, &pc, fors_sig, &at.md, &mut adrs);
    Ok(ht_verify(
        &p,
        &pc,
        &fors_pk,
        ht_sig,
        at.idx_tree,
        at.idx_leaf,
        pk_root,
    ))
}

// =========================== Public Size Helpers ============================

pub fn public_key_bytes(v: SphincsVariant) -> usize {
    param_set(v).pk_bytes
}
pub fn secret_key_bytes(v: SphincsVariant) -> usize {
    param_set(v).sk_bytes
}
pub fn signature_bytes(v: SphincsVariant) -> usize {
    param_set(v).sig_bytes
}

// ===================== Default Variant Wrappers ==========================

/// Sign a message using SPHINCS+ with default variant (SPX256f).
pub fn sphincs_sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    sign(SphincsVariant::SPX256f, sk, msg)
}

/// Verify a SPHINCS+ signature using default variant (SPX256f).
/// Returns Ok(true) if valid, Ok(false) if invalid, or Err on other errors.
pub fn sphincs_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, Error> {
    verify(SphincsVariant::SPX256f, pk, msg, sig)
}

// ============================ Call recording ================================

/// Every hash call of a key generation, a signature or a verification,
/// recorded by its address in this crate's unit tests only, so the tests
/// can assert on the construction's structure rather than on a round trip
/// (a defect the signer and the verifier share survives every round trip).
#[cfg(test)]
mod trace {
    use std::cell::RefCell;
    use std::collections::HashMap;

    pub(super) const ROLE_THASH: u8 = 1;
    pub(super) const ROLE_PRF: u8 = 2;

    /// Each address seen, with the digest of the role and input it was
    /// first hashed with, and every address later hashed with another.
    #[derive(Default)]
    pub(super) struct Calls {
        pub(super) by_adrs: HashMap<[u8; 32], [u8; 32]>,
        pub(super) reused: Vec<[u8; 32]>,
    }

    thread_local! {
        static ACTIVE: RefCell<Option<Calls>> = const { RefCell::new(None) };
    }

    pub(super) fn record(adrs: &[u8; 32], role: u8, inputs: &[&[u8]]) {
        ACTIVE.with(|active| {
            if let Some(calls) = active.borrow_mut().as_mut() {
                let mut h = blake3::Hasher::new();
                h.update(&[role]);
                for input in inputs {
                    h.update(input);
                }
                let digest = *h.finalize().as_bytes();
                match calls.by_adrs.get(adrs) {
                    Some(first) if *first != digest => calls.reused.push(*adrs),
                    Some(_) => {}
                    None => {
                        calls.by_adrs.insert(*adrs, digest);
                    }
                }
            }
        });
    }

    /// Run `f` with recording on, and return what it recorded.
    pub(super) fn capture<T>(f: impl FnOnce() -> T) -> (T, Option<Calls>) {
        ACTIVE.with(|active| *active.borrow_mut() = Some(Calls::default()));
        let out = f();
        (out, ACTIVE.with(|active| active.borrow_mut().take()))
    }
}

// ================================= Tests ====================================

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods, clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    const DEPLOYED: [SphincsVariant; 2] = [SphincsVariant::SPX128f, SphincsVariant::SPX256f];
    const ALL: [SphincsVariant; 6] = [
        SphincsVariant::SPX128s,
        SphincsVariant::SPX128f,
        SphincsVariant::SPX192s,
        SphincsVariant::SPX192f,
        SphincsVariant::SPX256s,
        SphincsVariant::SPX256f,
    ];

    fn key(v: SphincsVariant, fill: u8) -> SphincsKeyPair {
        generate_keypair_from_seed(v, &[fill; 32]).expect("key generation")
    }

    fn word(adrs: &[u8; 32], i: usize) -> u32 {
        u32::from_be_bytes(adrs[i * 4..(i + 1) * 4].try_into().expect("a word"))
    }

    /// The indices `sk` signs `m` at, from the signature's own `R`.
    fn indices_of(v: SphincsVariant, kp: &SphincsKeyPair, m: &[u8], sig: &[u8]) -> Indices {
        let p = param_set(v);
        let pk = &kp.public_key;
        split_digest(&p, &h_msg(&p, &sig[..p.n], &pk[..p.n], &pk[p.n..], m))
    }

    #[test]
    fn sizes_and_digest_lengths_are_fips_205s() {
        let expected = [
            (SphincsVariant::SPX128s, 7_856, 30),
            (SphincsVariant::SPX128f, 17_088, 34),
            (SphincsVariant::SPX192s, 16_224, 39),
            (SphincsVariant::SPX192f, 35_664, 42),
            (SphincsVariant::SPX256s, 29_792, 47),
            (SphincsVariant::SPX256f, 49_856, 49),
        ];
        for (v, sig, m) in expected {
            let p = param_set(v);
            assert_eq!(signature_bytes(v), sig, "{v:?} signature");
            assert_eq!(p.m, m, "{v:?} H_msg length");
            assert_eq!(p.len2, 3, "{v:?} len2");
            assert_eq!(public_key_bytes(v), 2 * p.n);
            assert_eq!(secret_key_bytes(v), 4 * p.n);
        }
    }

    #[test]
    fn the_address_is_the_fips_205_layout() {
        let mut adrs = Adrs::new();
        adrs.set_layer(0x0102_0304);
        adrs.set_tree(0x1112_1314_1516_1718);
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_keypair(0x2122_2324);
        adrs.set_chain(0x3132_3334);
        adrs.set_hash(0x4142_4344);
        let mut expected = Adrs::new().as_bytes();
        expected[..4].copy_from_slice(&[1, 2, 3, 4]);
        expected[8..16].copy_from_slice(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
        expected[20..24].copy_from_slice(&[0x21, 0x22, 0x23, 0x24]);
        expected[24..28].copy_from_slice(&[0x31, 0x32, 0x33, 0x34]);
        expected[28..32].copy_from_slice(&[0x41, 0x42, 0x43, 0x44]);
        assert_eq!(adrs.as_bytes(), expected);
    }

    #[test]
    fn changing_the_address_type_clears_every_type_specific_word() {
        let mut adrs = Adrs::new();
        adrs.set_layer(3);
        adrs.set_tree(9);
        adrs.set_type_and_clear(WOTS_HASH);
        adrs.set_keypair(5);
        adrs.set_chain(6);
        adrs.set_hash(7);
        adrs.set_type_and_clear(TREE);
        let bytes = adrs.as_bytes();
        assert_eq!(word(&bytes, 0), 3);
        assert_eq!(word(&bytes, 3), 9);
        assert_eq!(word(&bytes, 4), TREE);
        assert_eq!(&bytes[20..], &[0u8; 12]);
    }

    #[test]
    fn base_2b_and_the_wots_checksum_follow_fips_205() {
        assert_eq!(base_2b(&[0x12, 0x34], 4, 4), [1, 2, 3, 4]);
        assert_eq!(base_2b(&[0xAB, 0xCD, 0xEF], 6, 4), [42, 60, 55, 47]);
        let p = param_set(SphincsVariant::SPX128f);
        // A zero message: every digit 0, checksum len1·15 = 480 = 0x1E0.
        let digits = wots_digits(&p, &[0u8; 16]);
        assert_eq!(digits.len(), p.len);
        assert!(digits[..p.len1].iter().all(|d| *d == 0));
        assert_eq!(&digits[p.len1..], &[1, 14, 0]);
    }

    /// No address is hashed twice with different inputs, or under two roles,
    /// across a key generation, three signatures and their verifications.
    /// This is the separation a SPHINCS+-style proof assumes; version 1
    /// failed it at the WOTS+ compression (the hashtree's own addresses), at
    /// the FORS leaves (height 0 shared with the first internal level) and
    /// at every PRF call (the secret drawn under its chain's address).
    #[test]
    fn every_hash_call_has_its_own_address() {
        for v in DEPLOYED {
            let ((), recorded) = trace::capture(|| {
                let kp = key(v, 0x5A);
                for m in [&b"first"[..], &b"second"[..], &b"third"[..]] {
                    let sig = sign(v, &kp.secret_key, m).unwrap();
                    assert!(verify(v, &kp.public_key, m, &sig).unwrap());
                }
            });
            let calls = recorded.expect("recording was on");
            assert!(calls.by_adrs.len() > 1000, "{v:?}: the calls were recorded");
            let types: std::collections::BTreeSet<u32> =
                calls.by_adrs.keys().map(|a| word(a, 4)).collect();
            assert_eq!(
                types,
                [WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF]
                    .into_iter()
                    .collect(),
                "{v:?}: each role hashes under its own address type"
            );
            assert!(
                calls.reused.is_empty(),
                "{v:?}: {} addresses were hashed with two different inputs or roles, first {:02x?}",
                calls.reused.len(),
                calls.reused.first()
            );
        }
    }

    /// A FORS key belongs to the hypertree leaf that signs it: every FORS
    /// address a signature uses sits at layer 0, in the signing tree, with
    /// the signing leaf as its key pair. Version 1 left the key pair to the
    /// FORS tree number, so all leaves of a bottom tree shared one FORS key.
    #[test]
    fn a_fors_key_belongs_to_the_leaf_that_signs_it() {
        for v in DEPLOYED {
            let kp = key(v, 0x3C);
            let m = b"a message for the FORS binding";
            let (sig, recorded) = trace::capture(|| sign(v, &kp.secret_key, m).unwrap());
            let calls = recorded.expect("recording was on");
            let at = indices_of(v, &kp, m, &sig);
            let fors: Vec<&[u8; 32]> = calls
                .by_adrs
                .keys()
                .filter(|a| matches!(word(a, 4), FORS_TREE | FORS_PRF | FORS_ROOTS))
                .collect();
            let p = param_set(v);
            assert_eq!(
                fors.len(),
                // k·2^a secrets, k·(2^(a+1) − 1) tree nodes, one roots call.
                p.k * (1 << p.a) + p.k * ((1 << (p.a + 1)) - 1) + 1,
                "{v:?}: every FORS call of one signature"
            );
            for adrs in fors {
                assert_eq!(word(adrs, 0), 0, "{v:?}: FORS is at layer 0");
                assert_eq!(
                    (u64::from(word(adrs, 2)) << 32) | u64::from(word(adrs, 3)),
                    at.idx_tree,
                    "{v:?}: FORS is in the signing tree"
                );
                assert_eq!(
                    word(adrs, 5),
                    at.idx_leaf,
                    "{v:?}: FORS is the signing leaf's"
                );
            }
        }
    }

    /// Two leaves of one tree hold two FORS keys.
    #[test]
    fn two_leaves_of_one_tree_hold_different_fors_keys() {
        let v = SphincsVariant::SPX128f;
        let p = param_set(v);
        let kp = key(v, 0x11);
        let pc = PublicCtx::new(p.n, &kp.public_key[..p.n]);
        let sc = SecretCtx::new(&kp.secret_key[..p.n]);
        let md = vec![0x77u8; p.md_bytes];
        let fors_pk = |leaf: u32| {
            let at = Indices {
                md: md.clone(),
                idx_tree: 4,
                idx_leaf: leaf,
            };
            let mut adrs = fors_adrs(&at);
            let sig = fors_sign(&p, &pc, &sc, &md, &mut adrs);
            fors_pk_from_sig(&p, &pc, &sig, &md, &mut adrs)
        };
        assert_ne!(fors_pk(1), fors_pk(2));
    }

    /// `PRF` takes `PK.seed`: one `SK.seed` under two public seeds draws
    /// two secrets at one address, so a multi-key search cannot pool the
    /// top-layer addresses every key shares.
    #[test]
    fn the_prf_binds_the_public_seed() {
        let sc = SecretCtx::new(&[0x42; 32]);
        let mut adrs = Adrs::new();
        adrs.set_type_and_clear(WOTS_PRF);
        let one = prf(&PublicCtx::new(32, &[1; 32]), &sc, &adrs);
        let other = prf(&PublicCtx::new(32, &[2; 32]), &sc, &adrs);
        assert_ne!(*one, *other);
    }

    #[test]
    fn each_variant_signs_and_verifies() {
        for v in ALL {
            let kp = key(v, 0x07);
            let sig = sign(v, &kp.secret_key, b"each variant").unwrap();
            assert_eq!(sig.len(), signature_bytes(v));
            assert!(
                verify(v, &kp.public_key, b"each variant", &sig).unwrap(),
                "{v:?}"
            );
            assert!(
                !verify(v, &kp.public_key, b"another message", &sig).unwrap(),
                "{v:?}"
            );
        }
    }

    #[test]
    fn signing_is_deterministic_and_keys_follow_their_seed() {
        let v = SphincsVariant::SPX128f;
        assert_eq!(key(v, 0x01).secret_key, key(v, 0x01).secret_key);
        assert_ne!(key(v, 0x01).public_key, key(v, 0x02).public_key);
        let kp = key(v, 0x01);
        assert_eq!(
            sign(v, &kp.secret_key, b"same").unwrap(),
            sign(v, &kp.secret_key, b"same").unwrap()
        );
    }

    #[test]
    fn diagnostics_do_not_disclose_the_signing_seed() {
        let pair = SphincsKeyPair {
            public_key: vec![17; 32],
            secret_key: vec![239; 64],
        };
        let diagnostic = std::format!("{pair:?}");
        assert!(!diagnostic.contains("239"));
        assert!(diagnostic.contains("public_key"));
    }

    #[test]
    fn an_empty_message_or_a_short_key_is_refused() {
        let v = SphincsVariant::SPX128f;
        let kp = key(v, 0x09);
        assert_eq!(
            sign(v, &kp.secret_key, b"").unwrap_err(),
            Error::Crypto("Cannot sign empty message")
        );
        assert_eq!(
            sign(v, &kp.secret_key[1..], b"m").unwrap_err(),
            Error::Crypto("Bad secret key size")
        );
        let sig = sign(v, &kp.secret_key, b"m").unwrap();
        assert_eq!(
            verify(v, &kp.public_key, b"", &sig).unwrap_err(),
            Error::Crypto("Cannot verify empty message")
        );
    }

    /// A signature is verified before it leaves `sign`: under a secret key
    /// whose `PK.root` is not the root its seeds build, nothing is signed.
    #[test]
    fn a_secret_key_whose_root_is_not_its_own_signs_nothing() {
        let v = SphincsVariant::SPX128f;
        let p = param_set(v);
        let mut sk = key(v, 0x44).secret_key.clone();
        sk[3 * p.n] ^= 1;
        assert!(
            matches!(sign(v, &sk, b"m"), Err(Error::Crypto(why)) if why.contains("does not verify"))
        );
    }

    /// A signature or key of any other length does not verify, and neither
    /// does a signature checked under another variant.
    #[test]
    fn a_malformed_signature_or_key_does_not_verify() {
        for v in DEPLOYED {
            let kp = key(v, 0x21);
            let m = b"malformed";
            let sig = sign(v, &kp.secret_key, m).unwrap();
            let mut longer = sig.clone();
            longer.push(0);
            for bad in [&[][..], &sig[..1], &sig[..sig.len() - 1], &longer[..]] {
                assert!(
                    !verify(v, &kp.public_key, m, bad).unwrap(),
                    "{v:?} sig len {}",
                    bad.len()
                );
            }
            let mut long_pk = kp.public_key.clone();
            long_pk.push(0);
            for bad in [&kp.public_key[1..], &long_pk[..]] {
                assert!(
                    !verify(v, bad, m, &sig).unwrap(),
                    "{v:?} pk len {}",
                    bad.len()
                );
            }
            for other in ALL.into_iter().filter(|o| *o != v) {
                assert!(
                    !verify(other, &kp.public_key, m, &sig).unwrap(),
                    "{v:?} under {other:?}"
                );
            }
        }
    }

    /// One flipped bit in any n-byte block of a signature, in the public key
    /// or in the message, and the signature does not verify. The flipped bit
    /// moves through all eight positions as the block advances.
    #[test]
    fn a_flipped_bit_anywhere_in_a_signature_does_not_verify() {
        for v in DEPLOYED {
            let p = param_set(v);
            let kp = key(v, 0x33);
            let m = b"every block";
            let sig = sign(v, &kp.secret_key, m).unwrap();
            for block in 0..sig.len() / p.n {
                let mut bent = sig.clone();
                bent[block * p.n + block % p.n] ^= 1 << (block % 8);
                assert!(
                    !verify(v, &kp.public_key, m, &bent).unwrap(),
                    "{v:?} block {block}"
                );
            }
            for byte in 0..kp.public_key.len() {
                let mut pk = kp.public_key.clone();
                pk[byte] ^= 0x80;
                assert!(!verify(v, &pk, m, &sig).unwrap(), "{v:?} pk byte {byte}");
            }
            let mut other = m.to_vec();
            other[0] ^= 1;
            assert!(
                !verify(v, &kp.public_key, &other, &sig).unwrap(),
                "{v:?} message"
            );
        }
    }

    /// Frozen digests of a key and a signature for each deployed variant.
    /// They are regression tripwires, not known-answer tests: no external
    /// implementation shares this instantiation. A change here is a change
    /// to every DSM key and signature.
    #[test]
    fn frozen_construction_vectors() {
        let expected: [(SphincsVariant, [u8; 32], [u8; 32]); 2] = [
            (SphincsVariant::SPX128f, FROZEN_128F_PK, FROZEN_128F_SIG),
            (SphincsVariant::SPX256f, FROZEN_256F_PK, FROZEN_256F_SIG),
        ];
        for (v, pk_digest, sig_digest) in expected {
            let kp = key(v, 0xD5);
            let sig = sign(v, &kp.secret_key, b"DSM SPHINCS+ construction vector").unwrap();
            assert_eq!(
                *blake3::hash(&kp.public_key).as_bytes(),
                pk_digest,
                "{v:?} pk"
            );
            assert_eq!(*blake3::hash(&sig).as_bytes(), sig_digest, "{v:?} sig");
        }
    }

    const FROZEN_128F_PK: [u8; 32] = [
        178, 204, 107, 84, 3, 23, 150, 109, 223, 12, 114, 75, 196, 67, 239, 116, 140, 90, 42, 184,
        38, 132, 253, 57, 231, 50, 31, 224, 143, 162, 51, 212,
    ];
    const FROZEN_128F_SIG: [u8; 32] = [
        34, 204, 64, 137, 94, 146, 143, 83, 88, 183, 115, 21, 128, 234, 188, 89, 40, 10, 77, 119,
        172, 120, 198, 189, 137, 32, 208, 131, 150, 51, 161, 63,
    ];
    const FROZEN_256F_PK: [u8; 32] = [
        74, 142, 127, 239, 61, 238, 172, 248, 45, 166, 115, 205, 57, 112, 72, 181, 229, 112, 134,
        70, 131, 204, 29, 58, 193, 37, 220, 238, 40, 189, 62, 95,
    ];
    const FROZEN_256F_SIG: [u8; 32] = [
        185, 69, 62, 11, 156, 73, 32, 209, 209, 30, 112, 216, 134, 235, 124, 33, 173, 186, 110,
        120, 78, 143, 179, 74, 190, 63, 115, 182, 191, 213, 14, 239,
    ];
}
