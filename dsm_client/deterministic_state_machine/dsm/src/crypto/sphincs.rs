//! SPHINCS+ (BLAKE3-only) — DSM Module
//!
//! **SECURITY NOTICE:** This is a custom SPHINCS+ implementation using BLAKE3
//! instead of SHA2/SHAKE. It has NOT been formally audited by a third party.
//! Do NOT use in production for financial or security-critical applications
//! until a formal cryptographic audit has been completed.
//!
//! This module implements SPHINCS+ using **BLAKE3** for all hash, PRF,
//! and thash operations. The structure (FORS + WOTS+ + Hypertree) and
//! sizes match the standardized parameter sets. We expose six presets:
//!
//! - `SphincsVariant::SPX128s`  (n=16, h=63,  d=7,  a=12, k=14) → sig  7_856 bytes
//! - `SphincsVariant::SPX128f`  (n=16, h=66,  d=22, a=6,  k=33) → sig 17_088 bytes
//! - `SphincsVariant::SPX192s`  (n=24, h=63,  d=7,  a=14, k=17) → sig 16_224 bytes
//! - `SphincsVariant::SPX192f`  (n=24, h=66,  d=22, a=8,  k=33) → sig 35_664 bytes
//! - `SphincsVariant::SPX256s`  (n=32, h=64,  d=8,  a=14, k=22) → sig 29_792 bytes
//! - `SphincsVariant::SPX256f`  (n=32, h=68,  d=17, a=9,  k=35) → sig 49_856 bytes
//!
//! # Security Assumptions
//! - Security is derived from the *hash function only*. We use BLAKE3 in keyed
//!   mode for PRFs and thash, and unkeyed for message hashing / H_msg expanson.
//! - PRFs: BLAKE3 keyed hash; domain separation via address encoding.
//! - thash: BLAKE3 keyed hash; domain separation via address + pub_seed.
//! - WOTS+: w = 16; length computed per n following spec; checksum included.
//! - FORS: k trees of height a; signature contains k secret-leaf values and
//!   k authentication paths; the k roots are compressed into the FORS pk with thash.
//! - Hypertree: D layers; bottom FORS pk is signed by WOTS+ (leaf), then each
//!   layer authenticates upwards with Merkle authentication paths.
//!
//! # Performance Characteristics
//! - Keygen builds only the **top-layer** Merkle tree fully (2^(h/D) leaves).
//! - Sign computes FORS auth paths (2^a per tree in the naive builder here).
//!   This is correct and simple; you can replace with a streaming treehash
//!   algorithm later to reduce memory/CPU.
//! - Verify is fast (single path per layer).
//!
//! # DSM Integration Guidance
//! - Choose a **variant** at the callsite and pass it to every API:
//!   - `generate_keypair(variant)`
//!   - `sign(variant, sk, message)`
//!   - `verify(variant, pk, message, signature)`
//! - Store keys in DSM as returned here:
//!   - `pk = pub_seed || root`  (2n bytes)
//!   - `sk = sk_seed || sk_prf || pub_seed || root` (4n bytes)
//! - Use `sizes(variant)` to allocate buffers before I/O.
//!
//! # Important
//! This file intentionally does **not** depend on PQClean or other SHA2/SHAKE
//! codepaths; *everything is BLAKE3*. The signature sizes match the structural
//! parameter sets by keeping the same tree shapes/wots params.
//!
//! # Errors
//! All fallible operations return `DsmError`.

use crate::types::error::DsmError;
use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use subtle::ConstantTimeEq;
use tracing::{debug, error, info};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "sphincs-trace")]
macro_rules! sphincs_trace {
    ($($arg:tt)*) => {
        tracing::debug!($($arg)*);
    };
}

#[cfg(not(feature = "sphincs-trace"))]
macro_rules! sphincs_trace {
    ($($arg:tt)*) => {};
}

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

#[derive(Clone, Copy, Debug)]
struct Params {
    n: usize,    // hash length (bytes)
    h: usize,    // total merkle height
    d: usize,    // hypertree layers
    a: usize,    // FORS tree height
    k: usize,    // number of FORS trees
    w: usize,    // WOTS base (fixed 16)
    len1: usize, // WOTS len1
    len2: usize, // WOTS len2
    wots_len: usize,
    wots_bytes: usize,
    pk_bytes: usize,     // 2n
    sk_bytes: usize,     // 4n
    sig_bytes: usize,    // n (R) + k*(a+1)*n + d*wots_bytes + h*n
    layer_height: usize, // h/d
}

fn compute_wots_len2(len1: usize, w: usize) -> usize {
    // Standard WOTS+: len2 = floor(log_w(len1*(w-1))) + 1
    // For w = 16 and our sizes, this yields (n=16→3, n=24→3, n=32→3)
    let value = (len1 * (w - 1)) as f64;
    let logw = (w as f64).log2();

    (value.log2() / logw).floor() as usize + 1
}

fn param_set(v: SphincsVariant) -> Params {
    // canonical shapes from the SPHINCS+ spec (we keep tree shapes identical)
    // and compute sizes; hashing is BLAKE3-only (keyed/unkeyed), but sizes match.
    let (n, h, d, a, k) = match v {
        SphincsVariant::SPX128s => (16, 63, 7, 12, 14),
        SphincsVariant::SPX128f => (16, 66, 22, 6, 33),
        SphincsVariant::SPX192s => (24, 63, 7, 14, 17),
        SphincsVariant::SPX192f => (24, 66, 22, 8, 33),
        SphincsVariant::SPX256s => (32, 64, 8, 14, 22),
        SphincsVariant::SPX256f => (32, 68, 17, 9, 35),
    };
    let w = 16usize;
    let len1 = 2 * n; // ceil(8n / log2(w)) with log2(16)=4  => 2n exactly
    let len2 = compute_wots_len2(len1, w);
    let wots_len = len1 + len2;
    let wots_bytes = wots_len * n;
    let pk_bytes = 2 * n;
    let sk_bytes = 4 * n;
    let layer_height = h / d;
    let sig_bytes =
        n /*R*/ + k * (a + 1) * n /*FORS*/ + d * wots_bytes /*WOTS per layer*/ + h * n /*auth*/;
    Params {
        n,
        h,
        d,
        a,
        k,
        w,
        len1,
        len2,
        wots_len,
        wots_bytes,
        pk_bytes,
        sk_bytes,
        sig_bytes,
        layer_height,
    }
}

pub fn sizes(v: SphincsVariant) -> (usize, usize, usize) {
    let p = param_set(v);
    (p.pk_bytes, p.sk_bytes, p.sig_bytes)
}

// =============================== Address ====================================

#[derive(Clone, Copy, Debug, Default)]
struct SpxAddress {
    // 8 x 32-bit words as in the spec; we keep it simple and encode all parts here
    w: [u32; 8],
}

impl SpxAddress {
    fn new() -> Self {
        Self { w: [0; 8] }
    }
    fn set_type(&mut self, t: u32) {
        self.w[3] = t;
    }
    fn set_layer(&mut self, layer: u32) {
        self.w[0] = layer;
    }
    fn set_tree(&mut self, tree: u64) {
        self.w[1] = (tree >> 32) as u32;
        self.w[2] = tree as u32;
    }
    fn set_keypair(&mut self, keypair: u32) {
        self.w[5] = keypair;
    }
    fn set_chain(&mut self, chain: u32) {
        self.w[6] = chain;
    }
    fn set_hash(&mut self, h: u32) {
        self.w[7] = h;
    }
    fn set_tree_height(&mut self, h: u32) {
        self.w[4] = h;
    }
    fn set_tree_index(&mut self, i: u32) {
        // tree_index goes in word 5 (same position as keypair, but different address types)
        // keypair is used for WOTS (type 0), tree_index for HASHTREE (type 2) and FORS (types 4/5)
        self.w[5] = i;
    }
    #[allow(dead_code)]
    fn copy_subtree_from(&mut self, other: &SpxAddress) {
        self.w[0] = other.w[0];
        self.w[1] = other.w[1];
        self.w[2] = other.w[2];
    }
    fn as_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, word) in self.w.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

// =============================== Hash/PRF ===================================

fn blake3_kdf(out_len: usize, inputs: &[&[u8]]) -> Vec<u8> {
    let mut h = crate::crypto::blake3::dsm_domain_hasher("DSM/sphincs-kdf");
    for inp in inputs {
        h.update(inp);
    }
    let mut out = vec![0u8; out_len];
    let mut xof = h.finalize_xof();
    xof.fill(&mut out);
    out
}

fn blake3_keyed(n: usize, key: &[u8], inputs: &[&[u8]]) -> Vec<u8> {
    let mut keyarr = [0u8; 32];
    if key.len() >= 32 {
        keyarr.copy_from_slice(&key[..32]);
    } else {
        keyarr[..key.len()].copy_from_slice(key);
    }
    let mut h = blake3::Hasher::new_keyed(&keyarr);
    for inp in inputs {
        h.update(inp);
    }
    let mut out = vec![0u8; n];
    out.copy_from_slice(&h.finalize().as_bytes()[..n]);
    out
}

fn prf_addr(n: usize, sk_seed: &[u8], addr: &SpxAddress) -> Vec<u8> {
    blake3_keyed(n, sk_seed, &[&addr.as_bytes()])
}

fn thash(n: usize, pub_seed: &[u8], addr: &SpxAddress, inputs: &[&[u8]]) -> Vec<u8> {
    // Build a slice of byte-slices beginning with the encoded address, followed by inputs
    let addr_bytes = addr.as_bytes();
    let mut pieces: Vec<&[u8]> = Vec::with_capacity(1 + inputs.len());
    pieces.push(&addr_bytes);
    pieces.extend_from_slice(inputs);
    blake3_keyed(n, pub_seed, &pieces)
}

// ================================ WOTS+ =====================================

fn base_w_16(out_len: usize, bytes: &[u8]) -> Vec<u8> {
    // Convert to base-16 (nibbles)
    let mut out = Vec::with_capacity(out_len);
    for b in bytes {
        out.push(b >> 4);
        if out.len() == out_len {
            break;
        }
        out.push(b & 0x0F);
        if out.len() == out_len {
            break;
        }
    }
    while out.len() < out_len {
        out.push(0);
    }
    out
}

fn wots_len2_checksum(len1: usize, base: &[u8], w: usize) -> Vec<u8> {
    // cs = sum (w-1 - base[i])
    // Be robust to shorter base input in tests; production passes base.len()==len1.
    let mut cs: usize = 0;
    let take = core::cmp::min(len1, base.len());
    for b in base.iter().take(take) {
        cs += (w - 1) - (*b as usize);
    }
    // represent cs in base-w with len2 digits (most significant first)
    // since w=16, we can emit nibbles from high to low.
    let mut digits = Vec::new();
    let mut x = cs;
    while x > 0 {
        digits.push((x % 16) as u8);
        x /= 16;
    }
    digits.reverse();
    digits
}

fn wots_gen_sk_element(p: &Params, sk_seed: &[u8], addr: &SpxAddress) -> Vec<u8> {
    // addr should already have chain set by caller
    prf_addr(p.n, sk_seed, addr)
}

fn wots_chain(
    p: &Params,
    start: &[u8],
    start_step: usize,
    steps: usize,
    pub_seed: &[u8],
    addr: &SpxAddress,
) -> Vec<u8> {
    let mut val = start.to_vec();
    let mut a = *addr;
    for j in start_step..(start_step + steps) {
        a.set_hash(j as u32);
        val = thash(p.n, pub_seed, &a, &[&val]);
    }
    val
}

fn wots_gen_pk_vec(p: &Params, sk_seed: &[u8], pub_seed: &[u8], addr: &SpxAddress) -> Vec<u8> {
    // produce the vector (wots_len elements, each n bytes)
    let mut a = *addr;
    let mut out = vec![0u8; p.wots_bytes];
    for i in 0..p.wots_len {
        a.set_chain(i as u32);
        let sk_i = wots_gen_sk_element(p, sk_seed, &a);
        let pk_i = wots_chain(p, &sk_i, 0, p.w - 1, pub_seed, &a);
        out[i * p.n..(i + 1) * p.n].copy_from_slice(&pk_i);
    }
    out
}

fn wots_sig(
    p: &Params,
    msg: &[u8], // n bytes (message digest)
    sk_seed: &[u8],
    pub_seed: &[u8],
    addr: &SpxAddress,
) -> Vec<u8> {
    // message base-w representation
    let mut base = base_w_16(p.len1, msg);
    // checksum with fixed len2 = 3 typically; we normalize to exactly len2 digits
    let mut cs = wots_len2_checksum(p.len1, &base, p.w);
    // left-pad checksum to len2
    match cs.len().cmp(&p.len2) {
        std::cmp::Ordering::Less => {
            let mut pad = vec![0u8; p.len2 - cs.len()];
            pad.extend_from_slice(&cs);
            cs = pad;
        }
        std::cmp::Ordering::Greater => {
            cs = cs[cs.len() - p.len2..].to_vec();
        }
        std::cmp::Ordering::Equal => {}
    }
    base.extend_from_slice(&cs);
    debug_assert_eq!(base.len(), p.wots_len);

    // sign: for each i, compute chain(sk_i, 0 -> base[i])
    let mut sig = vec![0u8; p.wots_bytes];
    let mut a = *addr;
    for i in 0..p.wots_len {
        a.set_chain(i as u32);
        let sk_i = wots_gen_sk_element(p, sk_seed, &a);
        let s_i = wots_chain(p, &sk_i, 0, base[i] as usize, pub_seed, &a);
        sig[i * p.n..(i + 1) * p.n].copy_from_slice(&s_i);
    }
    sig
}

fn wots_pk_from_sig(
    p: &Params,
    sig: &[u8], // wots_bytes
    msg: &[u8], // n bytes
    pub_seed: &[u8],
    addr: &SpxAddress,
) -> Vec<u8> {
    let mut base = base_w_16(p.len1, msg);
    let mut cs = wots_len2_checksum(p.len1, &base, p.w);
    match cs.len().cmp(&p.len2) {
        std::cmp::Ordering::Less => {
            let mut pad = vec![0u8; p.len2 - cs.len()];
            pad.extend_from_slice(&cs);
            cs = pad;
        }
        std::cmp::Ordering::Greater => {
            cs = cs[cs.len() - p.len2..].to_vec();
        }
        std::cmp::Ordering::Equal => {}
    }
    base.extend_from_slice(&cs);

    let mut out_vec = vec![0u8; p.wots_bytes];
    let mut a = *addr;
    for i in 0..p.wots_len {
        a.set_chain(i as u32);
        let in_i = &sig[i * p.n..(i + 1) * p.n];
        // remaining steps = (w-1 - base[i])
        let pk_i = wots_chain(
            p,
            in_i,
            base[i] as usize,
            (p.w - 1) - base[i] as usize,
            pub_seed,
            &a,
        );
        out_vec[i * p.n..(i + 1) * p.n].copy_from_slice(&pk_i);
    }
    out_vec
}

// =============== l-tree (compress WOTS pk vector to single n-byte) ==========

fn l_tree(p: &Params, pub_seed: &[u8], addr: &SpxAddress, pk_vec: &mut [u8]) -> Vec<u8> {
    // pk_vec = len entries of n bytes
    let mut a = *addr;
    a.set_type(2); // HASHTREE domain (distinct from FORS/WOTS types)
    let mut count = p.wots_len;
    let mut layer = 0u32;
    while count > 1 {
        let mut idx = 0usize;
        let mut write = 0usize;
        while idx + 1 < count {
            a.set_tree_height(layer);
            a.set_tree_index((idx / 2) as u32);
            let left = &pk_vec[write * p.n..(write + 1) * p.n];
            let right = &pk_vec[(idx + 1) * p.n..(idx + 2) * p.n];
            let combined = thash(p.n, pub_seed, &a, &[left, right]);
            pk_vec[write * p.n..(write + 1) * p.n].copy_from_slice(&combined);
            idx += 2;
            write += 1;
        }
        if idx < count {
            // odd node, carry
            if write != idx {
                // Use a temporary buffer to avoid borrow conflicts
                let src = pk_vec[idx * p.n..(idx + 1) * p.n].to_vec();
                pk_vec[write * p.n..(write + 1) * p.n].copy_from_slice(&src);
            }
            write += 1;
        }
        count = write;
        layer += 1;
    }
    pk_vec[..p.n].to_vec()
}

fn wots_leaf(p: &Params, sk_seed: &[u8], pub_seed: &[u8], tree_addr: &SpxAddress) -> Vec<u8> {
    // generate WOTS pk vec → l-tree → leaf (n bytes)
    // we derive a WOTS address beneath the given tree address
    let mut waddr = *tree_addr;
    waddr.set_type(0); // WOTS
    let mut pk_vec = wots_gen_pk_vec(p, sk_seed, pub_seed, &waddr);
    l_tree(p, pub_seed, tree_addr, &mut pk_vec)
}

// ================================ FORS ======================================

#[derive(Debug, Clone)]
struct ForsSig {
    // flat encoding: for each tree t:
    //   SK_leaf (n bytes) || auth_path (a * n bytes)
    bytes: Vec<u8>,
}

fn fors_tree_leaf(
    p: &Params,
    sk_seed: &[u8],
    pub_seed: &[u8],
    addr: &SpxAddress,
    leaf_idx: u32,
) -> Vec<u8> {
    let mut a = *addr;
    a.set_tree_index(leaf_idx);
    let sk = prf_addr(p.n, sk_seed, &a);
    thash(p.n, pub_seed, &a, &[&sk])
}

fn build_auth_path_and_root(
    p: &Params,
    pub_seed: &[u8],
    addr: &SpxAddress,
    leaves: &mut [u8], // count * n
    idx: usize,
    height: usize,
) -> (Vec<u8>, Vec<u8>) {
    // Compute auth path for leaf idx and root (pairwise reduction)
    // leaves are level 0
    let _count = leaves.len() / p.n;
    let _a = *addr;
    let mut auth = vec![0u8; height * p.n];

    let mut current = leaves.to_vec();
    let mut layer = 0usize;
    let mut node_index = idx;

    while current.len() > p.n {
        // sibling index
        let sibling = if node_index.is_multiple_of(2) {
            node_index + 1
        } else {
            node_index - 1
        };
        let sib_bytes = &current[sibling * p.n..(sibling + 1) * p.n];
        // write layer-th auth node
        auth[layer * p.n..(layer + 1) * p.n].copy_from_slice(sib_bytes);

        // reduce current level
        let next_count = (current.len() / p.n).div_ceil(2);
        let mut next = vec![0u8; next_count * p.n];

        for (write, j) in (0..(current.len() / p.n)).step_by(2).enumerate() {
            let left = &current[j * p.n..(j + 1) * p.n];
            let right = if j + 1 < (current.len() / p.n) {
                &current[(j + 1) * p.n..(j + 2) * p.n]
            } else {
                left
            };
            let mut th = *addr;
            th.set_tree_height(layer as u32);
            th.set_tree_index((j / 2) as u32);
            // CRITICAL FIX: Always hash as [left, right] - this is correct since j is the left child index
            // The ordering matters for thash domain separation but we're already using the parent index
            let hnode = thash(p.n, pub_seed, &th, &[left, right]);
            next[write * p.n..(write + 1) * p.n].copy_from_slice(&hnode);
        }

        current = next;
        node_index /= 2;
        layer += 1;
    }

    (auth, current)
}

fn fors_sign(
    p: &Params,
    mhash: &[u8], // n bytes
    sk_seed: &[u8],
    pub_seed: &[u8],
    addr: &SpxAddress,
) -> (ForsSig, Vec<u8>) {
    // Derive k indices from mhash (k * a bits)
    let indices = message_to_indices(p, mhash);
    // For each tree, build leaves and auth path
    let leaf_count = 1usize << p.a;
    let mut a = *addr;
    a.set_type(4); // FORS TREE

    let mut sig_bytes = Vec::with_capacity(p.k * (1 + p.a) * p.n);
    let mut roots_concat = Vec::with_capacity(p.k * p.n);

    for (t, idx_u32) in indices.iter().enumerate() {
        a.set_keypair(t as u32); // Set keypair for each FORS tree
                                 // Build leaves for tree t
        let mut leaves = vec![0u8; leaf_count * p.n];
        for i in 0..leaf_count {
            a.set_tree_index(i as u32);
            let leaf = fors_tree_leaf(p, sk_seed, pub_seed, &a, i as u32);
            leaves[i * p.n..(i + 1) * p.n].copy_from_slice(&leaf);
        }

        // Secret leaf value (sk), then auth path for the chosen index
        let idx = *idx_u32 as usize;
        a.set_tree_height(0); // Set tree height for leaf operations
        a.set_tree_index(idx as u32);
        let sk_leaf = prf_addr(p.n, sk_seed, &a);
        sig_bytes.extend_from_slice(&sk_leaf);

        let (auth, root) = build_auth_path_and_root(p, pub_seed, &a, &mut leaves, idx, p.a);
        sig_bytes.extend_from_slice(&auth);
        roots_concat.extend_from_slice(&root);
    }

    // compress k roots into FORS pk with domain-separated thash
    let mut pk_addr = *addr;
    pk_addr.set_type(5); // FORS PK
    let fors_pk = thash(p.n, pub_seed, &pk_addr, &[&roots_concat]);

    (ForsSig { bytes: sig_bytes }, fors_pk)
}

fn fors_pk_from_sig(
    p: &Params,
    mhash: &[u8],
    sig: &ForsSig,
    pub_seed: &[u8],
    addr: &SpxAddress,
) -> Vec<u8> {
    let indices = message_to_indices(p, mhash);
    let mut roots_concat = Vec::with_capacity(p.k * p.n);
    let mut offset = 0usize;

    let mut a = *addr;
    a.set_type(4); // FORS TREE

    for (t, idx_u32) in indices.iter().enumerate() {
        a.set_keypair(t as u32); // Set keypair for each FORS tree
        let idx = *idx_u32 as usize;
        let sk_leaf = &sig.bytes[offset..offset + p.n];
        offset += p.n;

        // Hash the leaf with proper address (tree_height=0, tree_index=idx)
        a.set_tree_height(0);
        a.set_tree_index(idx as u32);
        let mut node = thash(p.n, pub_seed, &a, &[sk_leaf]);

        // ascend using auth path
        for h in 0..p.a {
            let auth = &sig.bytes[offset..offset + p.n];
            offset += p.n;

            let mut th = a;
            th.set_tree_height(h as u32);
            // Parent index is floor(idx / 2^(h + 1)). Using the same
            // convention as the signer ensures identical domain separation.
            th.set_tree_index((idx >> (h + 1)) as u32);

            if ((idx >> h) & 1) == 0 {
                node = thash(p.n, pub_seed, &th, &[&node, auth]);
            } else {
                node = thash(p.n, pub_seed, &th, &[auth, &node]);
            }
        }

        roots_concat.extend_from_slice(&node);
    }

    let mut pk_addr = *addr;
    pk_addr.set_type(5);
    thash(p.n, pub_seed, &pk_addr, &[&roots_concat])
}

fn message_to_indices(p: &Params, mhash: &[u8]) -> Vec<u32> {
    // Use k*a bits from mhash. If not enough, expand with BLAKE3 XOF.
    let need_bits = p.k * p.a;
    let mut bytes = mhash.to_vec();
    if bytes.len() * 8 < need_bits {
        let extra = blake3_kdf(need_bits.div_ceil(8) - bytes.len(), &[mhash]);
        bytes.extend_from_slice(&extra);
    }

    let mut out = Vec::with_capacity(p.k);
    let mut bitpos = 0usize;
    for _ in 0..p.k {
        let mut idx = 0u32;
        for _ in 0..p.a {
            let byte = bytes[bitpos / 8];
            let bit = (byte >> (7 - (bitpos % 8))) & 1;
            idx = (idx << 1) | (bit as u32);
            bitpos += 1;
        }
        out.push(idx);
    }
    out
}

// ============================== Merkle Helpers ==============================

fn compute_root_with_auth(
    p: &Params,
    leaf: &[u8],
    auth_path: &[u8], // a sequence of p.layer_height * n bytes for that layer
    pub_seed: &[u8],
    addr: &SpxAddress,
    mut idx: usize,
) -> Vec<u8> {
    // Reconstruct Merkle root from leaf and authentication path.
    // Ordering MUST reflect the leaf index parity at each height: if the current
    // node is a right child, sibling goes on the left (sibling || node); otherwise
    // (node || sibling).
    let mut a = *addr;
    let mut node = leaf.to_vec();
    for h in 0..p.layer_height {
        a.set_tree_height(h as u32);
        // Parent index (for address domain separation)
        a.set_tree_index((idx >> 1) as u32);
        let sibling = &auth_path[h * p.n..(h + 1) * p.n];
        if (idx & 1) == 1 {
            // current node is right child
            node = thash(p.n, pub_seed, &a, &[sibling, &node]);
        } else {
            // current node is left child
            node = thash(p.n, pub_seed, &a, &[&node, sibling]);
        }
        idx >>= 1;
    }
    node
}

fn build_merkle_and_auth(
    p: &Params,
    leaf_count: usize,
    leaf_fn: &mut dyn FnMut(usize) -> Vec<u8>,
    pub_seed: &[u8],
    addr: &SpxAddress,
    idx: usize,
) -> (Vec<u8>, Vec<u8>) {
    let mut leaves = vec![0u8; leaf_count * p.n];
    for i in 0..leaf_count {
        let v = leaf_fn(i);
        leaves[i * p.n..(i + 1) * p.n].copy_from_slice(&v);
    }
    let (auth, root) =
        build_auth_path_and_root(p, pub_seed, addr, &mut leaves, idx, p.layer_height);
    (auth, root)
}

// ===================== H_msg: derive (mhash, tree, leaf) ====================

fn h_msg_expand(p: &Params, r: &[u8], pk: &[u8], m: &[u8]) -> (Vec<u8>, u64, u32) {
    // Output mhash (n bytes), tree (64-bit), leaf (32-bit, truncated to layer range)
    // Tree is masked to (h - h/d) bits, leaf to h/d bits
    let need = p.n + 8 + 4;
    let x = blake3_kdf(need, &[r, pk, m]);
    let mhash = x[0..p.n].to_vec();
    let mut tree_bytes = [0u8; 8];
    tree_bytes.copy_from_slice(&x[p.n..p.n + 8]);
    let tree_raw = u64::from_be_bytes(tree_bytes);
    // Mask tree to (h - layer_height) bits
    let tree_bits = p.h - p.layer_height;
    let tree = if tree_bits < 64 {
        tree_raw & ((1u64 << tree_bits) - 1)
    } else {
        tree_raw
    };
    let mut leaf_bytes = [0u8; 4];
    leaf_bytes.copy_from_slice(&x[p.n + 8..p.n + 12]);
    let leaf_raw = u32::from_be_bytes(leaf_bytes);
    let leaf = leaf_raw & ((1u32 << p.layer_height) - 1);
    (mhash, tree, leaf)
}

// =============================== Key Material ===============================

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SphincsKeyPair {
    pub public_key: Vec<u8>, // pub_seed || root
    pub secret_key: Vec<u8>, // sk_seed || sk_prf || pub_seed || root
}

pub fn generate_keypair(v: SphincsVariant) -> Result<SphincsKeyPair, DsmError> {
    let p = param_set(v);
    let mut sk = vec![0u8; p.sk_bytes];
    let mut pk = vec![0u8; p.pk_bytes];
    let mut rng = OsRng;

    // sk_seed | sk_prf | pub_seed | root
    rng.fill_bytes(&mut sk[..3 * p.n]);
    let (sk_seed, _sk_prf, pub_seed) = (&sk[..p.n], &sk[p.n..2 * p.n], &sk[2 * p.n..3 * p.n]);

    // Build top layer Merkle root (layer d-1), across 2^(h/d) leaves
    let leaf_count = 1usize << p.layer_height;
    let mut addr_top = SpxAddress::new();
    addr_top.set_type(2); // hashtree domain
    addr_top.set_layer((p.d - 1) as u32);
    addr_top.set_tree(0);

    let (_auth_dummy, root) = build_merkle_and_auth(
        &p,
        leaf_count,
        &mut |i| {
            let mut leaf_addr = addr_top;
            leaf_addr.set_keypair(i as u32);
            wots_leaf(&p, sk_seed, pub_seed, &leaf_addr)
        },
        pub_seed,
        &addr_top,
        0,
    );

    pk[..p.n].copy_from_slice(pub_seed);
    pk[p.n..2 * p.n].copy_from_slice(&root);
    sk[3 * p.n..4 * p.n].copy_from_slice(&root);

    Ok(SphincsKeyPair {
        public_key: pk,
        secret_key: sk,
    })
}

pub fn generate_keypair_from_seed(
    v: SphincsVariant,
    seed32: &[u8; 32],
) -> Result<SphincsKeyPair, DsmError> {
    let p = param_set(v);
    let mut sk = vec![0u8; p.sk_bytes];
    let mut pk = vec![0u8; p.pk_bytes];
    let mut rng = ChaCha20Rng::from_seed(*seed32);
    rng.fill_bytes(&mut sk[..3 * p.n]);
    let (sk_seed, _sk_prf, pub_seed) = (&sk[..p.n], &sk[p.n..2 * p.n], &sk[2 * p.n..3 * p.n]);

    let leaf_count = 1usize << p.layer_height;
    let mut addr_top = SpxAddress::new();
    addr_top.set_type(2);
    addr_top.set_layer((p.d - 1) as u32);
    addr_top.set_tree(0);

    let (_auth_dummy, root) = build_merkle_and_auth(
        &p,
        leaf_count,
        &mut |i| {
            let mut leaf_addr = addr_top;
            leaf_addr.set_keypair(i as u32);
            wots_leaf(&p, sk_seed, pub_seed, &leaf_addr)
        },
        pub_seed,
        &addr_top,
        0,
    );

    pk[..p.n].copy_from_slice(pub_seed);
    pk[p.n..2 * p.n].copy_from_slice(&root);
    sk[3 * p.n..4 * p.n].copy_from_slice(&root);

    Ok(SphincsKeyPair {
        public_key: pk,
        secret_key: sk,
    })
}

// =============================== Sign/Verify ================================

fn sig_randomizer(p: &Params, sk_prf: &[u8], m: &[u8]) -> Vec<u8> {
    // Deterministic "randomness" R = H(sk_prf || m)
    blake3_keyed(p.n, sk_prf, &[m])
}

/// Sign: returns a signature with exact size for the chosen variant.
/// Layout:
///   sig = R (n)
///       || FORS_SIG (k * (a+1) * n)
///       || for layer in 0..d-1: WOTS_SIG (wots_bytes) || AUTH_PATH (layer_height * n)
pub fn sign(
    v: SphincsVariant,
    sk: &[u8], // sk_seed || sk_prf || pub_seed || root
    m: &[u8],
) -> Result<Vec<u8>, DsmError> {
    if m.is_empty() {
        return Err(DsmError::crypto(
            "Cannot sign empty message",
            None::<std::io::Error>,
        ));
    }
    let p = param_set(v);
    if sk.len() != p.sk_bytes {
        return Err(DsmError::crypto(
            "Bad secret key size",
            None::<std::io::Error>,
        ));
    }

    let (sk_seed, sk_prf, pub_seed, root) = (
        &sk[..p.n],
        &sk[p.n..2 * p.n],
        &sk[2 * p.n..3 * p.n],
        &sk[3 * p.n..4 * p.n],
    );

    // 1) Generate R
    let r = sig_randomizer(&p, sk_prf, m);

    // 2) H_msg → (mhash, tree, leaf)
    let mut pk = vec![0u8; p.pk_bytes];
    pk[..p.n].copy_from_slice(pub_seed);
    pk[p.n..2 * p.n].copy_from_slice(root);

    let (mhash, tree, leaf_idx) = h_msg_expand(&p, &r, &pk, m);

    // 3) FORS sign
    let mut addr_fors = SpxAddress::new();
    addr_fors.set_type(4); // FORS TREE
    addr_fors.set_layer(0);
    addr_fors.set_tree(tree);
    let (fors_sig, fors_pk) = fors_sign(&p, &mhash, sk_seed, pub_seed, &addr_fors);
    sphincs_trace!("SIGN FORS pk: {:?}", &fors_pk[..p.n.min(8)]);

    // 4) Hypertree signing: D layers, start leaf = leaf_idx, tree = tree
    let mut sig = Vec::with_capacity(p.sig_bytes);
    sig.extend_from_slice(&r);
    sig.extend_from_slice(&fors_sig.bytes);

    let mut current_root = fors_pk;

    let mut cur_tree = tree;
    let mut cur_leaf = leaf_idx as usize;

    for layer in 0..p.d {
        // a) WOTS sign current_root at (layer, cur_tree, cur_leaf)
        let mut waddr = SpxAddress::new();
        waddr.set_type(0); // WOTS
        waddr.set_layer(layer as u32);
        waddr.set_tree(cur_tree);
        waddr.set_keypair(cur_leaf as u32);

        if layer == 0 {
            sphincs_trace!(
                "SIGN Layer 0 current_root (message to sign): {:?}",
                &current_root[..p.n.min(8)]
            );
        }

        let wsig = wots_sig(&p, &current_root, sk_seed, pub_seed, &waddr);
        sig.extend_from_slice(&wsig);

        // b) Authentication path for that leaf in this layer's Merkle tree
        let leaf_count = 1usize << p.layer_height;

        let mut taddr = waddr;
        taddr.set_type(2); // hashtree

        let (auth, root_l) = build_merkle_and_auth(
            &p,
            leaf_count,
            &mut |i| {
                let mut la = taddr;
                la.set_keypair(i as u32);
                let leaf = wots_leaf(&p, sk_seed, pub_seed, &la);
                if layer == 0 && i == cur_leaf {
                    sphincs_trace!("SIGN Layer 0 leaf at index {}: {:?}", i, &leaf[..8]);
                }
                leaf
            },
            pub_seed,
            &taddr,
            cur_leaf,
        );
        sig.extend_from_slice(&auth);

        current_root = root_l;

        // derive next layer's indices
        let mask = (1usize << p.layer_height) - 1;
        cur_leaf = (cur_tree as usize) & mask;
        cur_tree >>= p.layer_height as u32;
    }

    debug_assert_eq!(sig.len(), p.sig_bytes);
    Ok(sig)
}

pub fn verify(
    v: SphincsVariant,
    pk: &[u8], // pub_seed || root
    m: &[u8],
    sig: &[u8],
) -> Result<bool, DsmError> {
    if m.is_empty() {
        return Err(DsmError::crypto(
            "Cannot verify empty message",
            None::<std::io::Error>,
        ));
    }
    let p = param_set(v);
    if pk.len() != p.pk_bytes || sig.len() != p.sig_bytes {
        return Ok(false);
    }
    let (pub_seed, root) = (&pk[..p.n], &pk[p.n..2 * p.n]);

    // parse signature
    let mut off = 0usize;
    let r = &sig[off..off + p.n];
    off += p.n;

    let fors_sig_bytes = p.k * (p.a + 1) * p.n;
    let fors_bytes = &sig[off..off + fors_sig_bytes];
    off += fors_sig_bytes;

    let (mhash, tree, leaf_idx) = h_msg_expand(&p, r, pk, m);

    let mut addr_fors = SpxAddress::new();
    addr_fors.set_type(4);
    addr_fors.set_layer(0);
    addr_fors.set_tree(tree);

    let fors_sig = ForsSig {
        bytes: fors_bytes.to_vec(),
    };
    let mut current_root = fors_pk_from_sig(&p, &mhash, &fors_sig, pub_seed, &addr_fors);
    sphincs_trace!("VERIFY FORS pk: {:?}", &current_root[..p.n.min(8)]);

    let mut cur_tree = tree;
    let mut cur_leaf = leaf_idx as usize;

    for layer in 0..p.d {
        // Read WOTS sig
        let wsig = &sig[off..off + p.wots_bytes];
        off += p.wots_bytes;

        // Read auth path for this layer
        let auth = &sig[off..off + p.layer_height * p.n];
        off += p.layer_height * p.n;

        // Rebuild leaf: take WOTS sig, derive pk_vec back from message=current_root
        let mut waddr = SpxAddress::new();
        waddr.set_type(0);
        waddr.set_layer(layer as u32);
        waddr.set_tree(cur_tree);
        waddr.set_keypair(cur_leaf as u32);

        let pk_vec = wots_pk_from_sig(&p, wsig, &current_root, pub_seed, &waddr);

        if layer == 0 {
            sphincs_trace!("VERIFY Layer 0 pk_vec[0..8]: {:?}", &pk_vec[..8]);
            sphincs_trace!(
                "VERIFY Layer 0 current_root (message): {:?}",
                &current_root[..p.n.min(8)]
            );
        }

        // compress via l-tree
        // Copy address but keep layer/tree/keypair, only change type to HASHTREE
        let mut taddr = waddr;
        taddr.set_type(2);
        let mut tmp = pk_vec.clone();
        let leaf = l_tree(&p, pub_seed, &taddr, &mut tmp);

        if layer == 0 {
            sphincs_trace!(
                "VERIFY Layer 0 leaf at index {}: {:?}",
                cur_leaf,
                &leaf[..8]
            );
        }

        // ascend with auth path to get this layer root (pass leaf index for ordering)
        let root_l = compute_root_with_auth(&p, &leaf, auth, pub_seed, &taddr, cur_leaf);
        current_root = root_l;

        // derive next layer's indices
        let mask = (1usize << p.layer_height) - 1;
        cur_leaf = (cur_tree as usize) & mask;
        cur_tree >>= p.layer_height as u32;
    }

    let ok = current_root.ct_eq(root).unwrap_u8() == 1;
    Ok(ok)
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

// ================================ Init ======================================

pub fn init_sphincs() -> Result<(), DsmError> {
    // self-test a small variant for sanity and log supported variants
    info!("Initializing SPHINCS+ (BLAKE3-only) with 6 parameter sets");
    let v = SphincsVariant::SPX128s;
    let kp = generate_keypair(v)?;
    let msg = b"SPHINCS+ self-test message";
    let sig = sign(v, &kp.secret_key, msg)?;
    let ok = verify(v, &kp.public_key, msg, &sig)?;
    if !ok {
        error!("SPHINCS+ self-test failed");
        return Err(DsmError::crypto(
            "SPHINCS+ self-test failure".to_string(),
            None::<std::io::Error>,
        ));
    }
    debug!("SPHINCS+ self-test passed for {:?}", v);
    Ok(())
}

// ===================== Default Variant Wrappers ==========================

/// Generate SPHINCS+ keypair using default variant (SPX256f).
///
/// SPX256f (fast): ~10x faster keygen than SPX256s, larger signatures
/// (49,856 vs 29,792 bytes). Acceptable since genesis only signs once
/// and bilateral transfers are infrequent. Target: genesis < 2 seconds.
pub fn generate_sphincs_keypair() -> Result<(Vec<u8>, Vec<u8>), DsmError> {
    let kp = generate_keypair(SphincsVariant::SPX256f)?;
    Ok((kp.public_key.clone(), kp.secret_key.clone()))
}

/// Sign a message using SPHINCS+ with default variant (SPX256f).
pub fn sphincs_sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, DsmError> {
    sign(SphincsVariant::SPX256f, sk, msg)
}

/// Verify a SPHINCS+ signature using default variant (SPX256f).
/// Returns Ok(true) if valid, Ok(false) if invalid, or Err on other errors.
pub fn sphincs_verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, DsmError> {
    verify(SphincsVariant::SPX256f, pk, msg, sig)
}
// ================================= Tests ====================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_known() {
        assert_eq!(signature_bytes(SphincsVariant::SPX128s), 7_856);
        assert_eq!(signature_bytes(SphincsVariant::SPX128f), 17_088);
        assert_eq!(signature_bytes(SphincsVariant::SPX192s), 16_224);
        assert_eq!(signature_bytes(SphincsVariant::SPX192f), 35_664);
        assert_eq!(signature_bytes(SphincsVariant::SPX256s), 29_792);
        assert_eq!(signature_bytes(SphincsVariant::SPX256f), 49_856);

        assert_eq!(public_key_bytes(SphincsVariant::SPX256f), 64);
        assert_eq!(secret_key_bytes(SphincsVariant::SPX256f), 128);
    }

    #[test]
    fn sign_verify_each_variant() -> Result<(), DsmError> {
        let variants: &[SphincsVariant] = if cfg!(debug_assertions) {
            &[SphincsVariant::SPX128s, SphincsVariant::SPX256s]
        } else {
            &[
                SphincsVariant::SPX128s,
                SphincsVariant::SPX128f,
                SphincsVariant::SPX192s,
                SphincsVariant::SPX192f,
                SphincsVariant::SPX256s,
                SphincsVariant::SPX256f,
            ]
        };

        for v in variants {
            let kp = generate_keypair(*v)?;
            let m = b"test message";
            let sig = sign(*v, &kp.secret_key, m)?;
            assert_eq!(sig.len(), signature_bytes(*v));
            let ok = verify(*v, &kp.public_key, m, &sig)?;
            assert!(ok);
            let bad = verify(*v, &kp.public_key, b"oops", &sig)?;
            assert!(!bad);
        }
        Ok(())
    }

    #[test]
    fn deterministic_seeded_keygen() -> Result<(), DsmError> {
        let v = if cfg!(debug_assertions) {
            SphincsVariant::SPX128s
        } else {
            SphincsVariant::SPX256f
        };
        let seed = [42u8; 32];
        let kp1 = generate_keypair_from_seed(v, &seed)?;
        let kp2 = generate_keypair_from_seed(v, &seed)?;
        assert_eq!(kp1.public_key, kp2.public_key);
        assert_eq!(kp1.secret_key, kp2.secret_key);
        Ok(())
    }

    #[test]
    fn wots_base_and_checksum() {
        // sanity: 0xFF00AB → nibbles check
        let v = SphincsVariant::SPX128s;
        let p = param_set(v);
        let data = [0xFFu8, 0x00, 0xAB];
        let bw = super::base_w_16(6, &data);
        assert_eq!(bw, vec![0x0F, 0x0F, 0x00, 0x00, 0x0A, 0x0B]);

        let cs = super::wots_len2_checksum(p.len1, &bw[..p.len1.min(bw.len())], p.w);
        assert!(!cs.is_empty());
    }

    #[test]
    fn fors_sign_verify_round_trip() -> Result<(), DsmError> {
        // Test that FORS sign/verify produces consistent pk
        let v = SphincsVariant::SPX128s;
        let p = param_set(v);
        let sk_seed = vec![1u8; p.n];
        let pub_seed = vec![2u8; p.n];
        let mhash = vec![3u8; p.n];

        let mut addr = SpxAddress::new();
        addr.set_type(4);
        addr.set_layer(0);
        addr.set_tree(0);

        let (fors_sig, fors_pk_sign) = super::fors_sign(&p, &mhash, &sk_seed, &pub_seed, &addr);
        let fors_pk_verify = super::fors_pk_from_sig(&p, &mhash, &fors_sig, &pub_seed, &addr);

        assert_eq!(fors_pk_sign, fors_pk_verify, "FORS pk mismatch!");
        Ok(())
    }

    // ======================== Security-Critical Tests ========================
    // Additional tests for attack vectors and edge cases

    #[test]
    fn rejects_single_bit_flip_in_signature() {
        let v = SphincsVariant::SPX256s;
        let kp = generate_keypair(v).unwrap();
        let msg = b"test message for bit flip test";
        let mut sig = sign(v, &kp.secret_key, msg).unwrap();

        // Flip a bit early in signature (randomness R - first 32 bytes in SPX256s)
        // This should affect the message hash expansion and invalidate verification
        sig[16] ^= 0x01;

        let result = verify(v, &kp.public_key, msg, &sig).unwrap();
        assert!(
            !result,
            "Single bit flip in randomness R must invalidate signature"
        );
    }

    #[test]
    fn rejects_wrong_public_key() {
        let v = SphincsVariant::SPX256s;
        let kp1 = generate_keypair(v).unwrap();
        let kp2 = generate_keypair(v).unwrap();
        let msg = b"test message";
        let sig = sign(v, &kp1.secret_key, msg).unwrap();

        // Try to verify with wrong public key
        let result = verify(v, &kp2.public_key, msg, &sig).unwrap();
        assert!(!result, "Signature must not verify with wrong public key");
    }

    #[test]
    fn rejects_signature_replay_on_different_message() {
        let v = SphincsVariant::SPX256s;
        let kp = generate_keypair(v).unwrap();
        let msg1 = b"original message";
        let msg2 = b"different message";

        let sig = sign(v, &kp.secret_key, msg1).unwrap();
        let result = verify(v, &kp.public_key, msg2, &sig).unwrap();

        assert!(!result, "Signature must not verify for different message");
    }

    #[test]
    fn rejects_all_zero_signature() {
        let v = SphincsVariant::SPX256s;
        let kp = generate_keypair(v).unwrap();
        let msg = b"test message";
        let sig_len = signature_bytes(v);
        let zero_sig = vec![0u8; sig_len];

        let result = verify(v, &kp.public_key, msg, &zero_sig).unwrap();
        assert!(!result, "All-zero signature must not verify");
    }

    #[test]
    fn rejects_truncated_signature() {
        let v = SphincsVariant::SPX256s;
        let kp = generate_keypair(v).unwrap();
        let msg = b"test message";
        let sig = sign(v, &kp.secret_key, msg).unwrap();

        // Try with truncated signature
        let truncated = &sig[..sig.len() - 100];
        let result = verify(v, &kp.public_key, msg, truncated);

        // Should either reject via size check or fail verification
        match result {
            Ok(false) => {} // Valid rejection
            Err(_) => {}    // Error rejection is also acceptable
            Ok(true) => panic!("Truncated signature must not verify!"),
        }
    }

    #[test]
    fn message_prefix_extension_attack() {
        // Verify that message with prefix doesn't validate against longer message
        let v = SphincsVariant::SPX256s;
        let kp = generate_keypair(v).unwrap();
        let msg_short = b"short";
        let msg_long = b"short and longer message";

        let sig = sign(v, &kp.secret_key, msg_short).unwrap();
        let result = verify(v, &kp.public_key, msg_long, &sig).unwrap();

        assert!(!result, "Signature must not verify for extended message");
    }

    #[test]
    fn truncated_public_key_rejection() {
        let v = SphincsVariant::SPX256s;
        let kp = generate_keypair(v).unwrap();
        let msg = b"test message";
        let sig = sign(v, &kp.secret_key, msg).unwrap();

        // Truncate public key
        let truncated_pk = &kp.public_key[..kp.public_key.len() - 10];
        let result = verify(v, truncated_pk, msg, &sig);

        // Should reject due to size
        assert!(
            result.is_err() || !result.unwrap(),
            "Truncated public key must be rejected"
        );
    }
}
