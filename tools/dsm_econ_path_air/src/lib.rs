// SPDX-License-Identifier: MIT OR Apache-2.0

//! The economic SMT authentication path as a Plonky3 AIR.
//!
//! `R_econ` is a 256-level sparse Merkle tree whose internal nodes are
//! `econ_node(l, r) = BLAKE3(tag ‖ 0x00 ‖ l ‖ r)` with the 24-byte tag
//! `DSM/economic-smt-node/v1` (`dsm::economic::tree`). The message is 89
//! bytes, so one node is exactly two BLAKE3 compressions in one chunk: the
//! first over bytes `0..64` with the IV as chaining value and `CHUNK_START`,
//! the second over bytes `64..89` with the first's output as chaining value
//! and `CHUNK_END | ROOT`. The hash is the first eight output words of the
//! second compression.
//!
//! One trace row is one compression, proven by [`Blake3Air`] as a sub-AIR over
//! the first `NUM_BLAKE3_COLS` columns. Two rows make one level; 512 rows make
//! one path, folded leaf-to-root exactly as `root_from_path` folds it. The
//! columns after the BLAKE3 block carry the level's child digest (`current`)
//! and `sibling` as bits, and the constraints bind:
//!
//! - row A's message to `tag ‖ 0x00 ‖ left ‖ right` where `(left, right)` is
//!   `(current, sibling)` when the key bit is 0 and `(sibling, current)` when
//!   it is 1 — the key bit is a preprocessed column, fixed by the verifier
//!   from the key, never chosen by the prover;
//! - row B's chaining value to row A's output, and row B's message to the
//!   tail of `right`;
//! - the next level's `current` to row B's output;
//! - the first `current` of each path to the leaf public values and the last
//!   output to the root public values, as 16-bit limbs.
//!
//! A proof is over `N` paths (a power of two) with one key each, which is the
//! shape of a mutation: the pre-state path and the post-state path of one
//! leaf share a key and siblings and differ in the leaf.

use core::mem::offset_of;

use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_blake3_air::{Blake3Air, Blake3Cols, Blake3CompressionInput, NUM_BLAKE3_COLS};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SubAirBuilder;

/// `DSM/economic-smt-node/v1`, as `dsm::common::domain_tags` spells it.
pub const TAG_ECONOMIC_SMT_NODE: &[u8; 24] = b"DSM/economic-smt-node/v1";
/// `DSM/economic-smt-leaf/v1`.
pub const TAG_ECONOMIC_SMT_LEAF: &[u8; 24] = b"DSM/economic-smt-leaf/v1";
/// The tagged prefix `tag ‖ 0x00` (`dsm_domain_hasher`).
pub const PREFIX_LEN: usize = 25;
/// `tag ‖ 0x00 ‖ l ‖ r`.
pub const NODE_MSG_LEN: usize = PREFIX_LEN + 64;
/// Bytes of the message in the second block.
pub const TAIL_LEN: usize = NODE_MSG_LEN - 64;
/// Full 256-bit key space (`ECONOMIC_SMT_HEIGHT`).
pub const SMT_HEIGHT: usize = 256;
/// Two compressions per level.
pub const ROWS_PER_PATH: usize = 2 * SMT_HEIGHT;
/// Columns after the BLAKE3 block: `current` (256 bits) then `sibling` (256 bits).
pub const NUM_EXTRA_COLS: usize = 512;
/// Trace width.
pub const NUM_COLS: usize = NUM_BLAKE3_COLS + NUM_EXTRA_COLS;
/// Public values per path: leaf as 16 u16 limbs, root as 16 u16 limbs.
pub const PUBLIC_VALUES_PER_PATH: usize = 32;

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const ROOT: u32 = 8;

// ---------------------------------------------------------------------------
// BLAKE3 on the host, for trace construction and for the reference hash.
// ---------------------------------------------------------------------------

#[inline]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

/// The BLAKE3 compression function, all sixteen output words.
pub fn compress(input: &Blake3CompressionInput) -> [u32; 16] {
    let cv = input.chaining_value;
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        input.counter as u32,
        (input.counter >> 32) as u32,
        input.block_len,
        input.flags,
    ];
    let mut m = input.block;
    for r in 0..7 {
        round(&mut state, &m);
        if r < 6 {
            let old = m;
            for i in 0..16 {
                m[i] = old[MSG_PERMUTATION[i]];
            }
        }
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    state
}

fn words_le(bytes: &[u8]) -> [u32; 16] {
    let mut block = [0u8; 64];
    block[..bytes.len()].copy_from_slice(bytes);
    core::array::from_fn(|w| u32::from_le_bytes([block[4 * w], block[4 * w + 1], block[4 * w + 2], block[4 * w + 3]]))
}

fn digest_words(d: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|w| u32::from_le_bytes([d[4 * w], d[4 * w + 1], d[4 * w + 2], d[4 * w + 3]]))
}

fn digest_bytes(words: &[u32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (w, word) in words.iter().take(8).enumerate() {
        out[4 * w..4 * w + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// The two compressions of `econ_node(left, right)`, in order, and the node.
pub fn node_compressions(left: &[u8; 32], right: &[u8; 32]) -> ([Blake3CompressionInput; 2], [u8; 32]) {
    let mut msg = [0u8; NODE_MSG_LEN];
    msg[..24].copy_from_slice(TAG_ECONOMIC_SMT_NODE);
    msg[24] = 0;
    msg[PREFIX_LEN..PREFIX_LEN + 32].copy_from_slice(left);
    msg[PREFIX_LEN + 32..].copy_from_slice(right);
    let first = Blake3CompressionInput {
        chaining_value: IV,
        block: words_le(&msg[..64]),
        counter: 0,
        block_len: 64,
        flags: CHUNK_START,
    };
    let out_a = compress(&first);
    let second = Blake3CompressionInput {
        chaining_value: core::array::from_fn(|i| out_a[i]),
        block: words_le(&msg[64..]),
        counter: 0,
        block_len: TAIL_LEN as u32,
        flags: CHUNK_END | ROOT,
    };
    let out_b = compress(&second);
    ([first, second], digest_bytes(&out_b))
}

/// `econ_node` by the `blake3` crate — the reference the AIR is held to.
pub fn econ_node_reference(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(TAG_ECONOMIC_SMT_NODE);
    h.update(&[0u8]);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// `econ_leaf(key, value)` by the `blake3` crate.
pub fn econ_leaf_reference(key: &[u8; 32], value: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(TAG_ECONOMIC_SMT_LEAF);
    h.update(&[0u8]);
    h.update(key);
    h.update(value);
    *h.finalize().as_bytes()
}

/// `get_bit` as `dsm::merkle::sparse_merkle_tree` defines it: MSB-first.
pub fn get_bit(key: &[u8; 32], bit_index: usize) -> u8 {
    (key[bit_index / 8] >> (7 - (bit_index % 8))) & 1
}

/// The key bit consumed at step `i` of the leaf-to-root fold (`root_from_path`:
/// `level = HEIGHT - 1 - i`).
pub fn direction(key: &[u8; 32], step: usize) -> u8 {
    get_bit(key, SMT_HEIGHT - 1 - step)
}

/// `root_from_path` by the reference hash.
pub fn root_from_path_reference(key: &[u8; 32], leaf: &[u8; 32], siblings: &[[u8; 32]; SMT_HEIGHT]) -> [u8; 32] {
    let mut current = *leaf;
    for (i, sibling) in siblings.iter().enumerate() {
        current = if direction(key, i) == 0 {
            econ_node_reference(&current, sibling)
        } else {
            econ_node_reference(sibling, &current)
        };
    }
    current
}

// ---------------------------------------------------------------------------
// One path's witness.
// ---------------------------------------------------------------------------

/// One leaf-to-root path: what the prover knows.
#[derive(Clone)]
pub struct PathWitness {
    pub key: [u8; 32],
    pub leaf: [u8; 32],
    pub siblings: Box<[[u8; 32]; SMT_HEIGHT]>,
}

impl PathWitness {
    /// The root this path folds to.
    pub fn root(&self) -> [u8; 32] {
        root_from_path_reference(&self.key, &self.leaf, &self.siblings)
    }
}

/// A digest as sixteen u16 limbs, low limb first per word.
pub fn digest_limbs<F: PrimeField64>(d: &[u8; 32]) -> [F; 16] {
    let words = digest_words(d);
    core::array::from_fn(|i| {
        let w = words[i / 2];
        if i % 2 == 0 { F::from_u16(w as u16) } else { F::from_u16((w >> 16) as u16) }
    })
}

/// The public values for `paths`: per path, leaf limbs then root limbs.
pub fn public_values<F: PrimeField64>(paths: &[PathWitness]) -> Vec<F> {
    let mut pvs = Vec::with_capacity(paths.len() * PUBLIC_VALUES_PER_PATH);
    for p in paths {
        pvs.extend_from_slice(&digest_limbs::<F>(&p.leaf));
        pvs.extend_from_slice(&digest_limbs::<F>(&p.root()));
    }
    pvs
}

// ---------------------------------------------------------------------------
// Column layout.
// ---------------------------------------------------------------------------

const OFF_INPUTS: usize = offset_of!(Blake3Cols<u8>, inputs);
const OFF_CV: usize = offset_of!(Blake3Cols<u8>, chaining_values);
const OFF_COUNTER_LOW: usize = offset_of!(Blake3Cols<u8>, counter_low);
const OFF_COUNTER_HI: usize = offset_of!(Blake3Cols<u8>, counter_hi);
const OFF_BLOCK_LEN: usize = offset_of!(Blake3Cols<u8>, block_len);
const OFF_FLAGS: usize = offset_of!(Blake3Cols<u8>, flags);
const OFF_OUTPUTS: usize = offset_of!(Blake3Cols<u8>, outputs);
const OFF_CURRENT: usize = NUM_BLAKE3_COLS;
const OFF_SIBLING: usize = NUM_BLAKE3_COLS + 256;

/// Column of bit `j` of byte `b` of the 64-byte message block.
#[inline]
const fn input_bit(b: usize, j: usize) -> usize {
    OFF_INPUTS + 32 * (b / 4) + 8 * (b % 4) + j
}
/// Column of bit `k` of chaining-value word `w`.
#[inline]
const fn cv_bit(w: usize, k: usize) -> usize {
    OFF_CV + 32 * w + k
}
/// Column of bit `k` of output word `w` (`w < 8` is the hash).
#[inline]
const fn out_bit(w: usize, k: usize) -> usize {
    OFF_OUTPUTS + 32 * w + k
}
/// Column of bit `j` of byte `b` of a 32-byte digest held in `current`.
#[inline]
const fn current_bit(b: usize, j: usize) -> usize {
    OFF_CURRENT + 32 * (b / 4) + 8 * (b % 4) + j
}
/// Column of bit `j` of byte `b` of a 32-byte digest held in `sibling`.
#[inline]
const fn sibling_bit(b: usize, j: usize) -> usize {
    OFF_SIBLING + 32 * (b / 4) + 8 * (b % 4) + j
}

/// Preprocessed columns: `is_a`, `direction`, `is_path_start`, `is_path_end`,
/// then one selector per path.
const PRE_IS_A: usize = 0;
const PRE_DIRECTION: usize = 1;
const PRE_PATH_START: usize = 2;
const PRE_PATH_END: usize = 3;
const PRE_PATH_SEL: usize = 4;

// ---------------------------------------------------------------------------
// The AIR.
// ---------------------------------------------------------------------------

/// The economic SMT path AIR over `keys.len()` paths (a power of two), one key
/// each. The keys are the verifier's: they fix the preprocessed trace.
pub struct EconSmtPathAir {
    pub keys: Vec<[u8; 32]>,
}

impl EconSmtPathAir {
    pub fn new(keys: Vec<[u8; 32]>) -> Self {
        assert!(!keys.is_empty() && keys.len().is_power_of_two(), "paths must be a power of two");
        Self { keys }
    }

    pub fn num_paths(&self) -> usize {
        self.keys.len()
    }

    pub fn num_rows(&self) -> usize {
        self.keys.len() * ROWS_PER_PATH
    }

    fn preprocessed_width_(&self) -> usize {
        PRE_PATH_SEL + self.keys.len()
    }

    /// The main trace for `paths`, whose keys must be this AIR's keys in order.
    pub fn generate_trace<F: PrimeField64>(&self, paths: &[PathWitness], extra_capacity_bits: usize) -> RowMajorMatrix<F> {
        assert_eq!(paths.len(), self.keys.len());
        for (p, k) in paths.iter().zip(&self.keys) {
            assert_eq!(&p.key, k, "path key is not the AIR's key");
        }
        let mut inputs = Vec::with_capacity(self.num_rows());
        // (current, sibling) per row A; zero on row B.
        let mut extras: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(self.num_rows());
        for p in paths {
            let mut current = p.leaf;
            for (i, sibling) in p.siblings.iter().enumerate() {
                let (left, right) = if direction(&p.key, i) == 0 { (current, *sibling) } else { (*sibling, current) };
                let (two, node) = node_compressions(&left, &right);
                inputs.push(two[0].clone());
                inputs.push(two[1].clone());
                extras.push((current, *sibling));
                extras.push(([0u8; 32], [0u8; 32]));
                current = node;
            }
        }
        let blake = p3_blake3_air::generate_trace_rows_with_inputs::<F>(inputs, 0);
        let rows = self.num_rows();
        let mut values = F::zero_vec((rows * NUM_COLS) << extra_capacity_bits);
        values.truncate(rows * NUM_COLS);
        for r in 0..rows {
            let dst = &mut values[r * NUM_COLS..(r + 1) * NUM_COLS];
            dst[..NUM_BLAKE3_COLS].copy_from_slice(&blake.values[r * NUM_BLAKE3_COLS..(r + 1) * NUM_BLAKE3_COLS]);
            let (cur, sib) = extras[r];
            for b in 0..32 {
                for j in 0..8 {
                    dst[current_bit(b, j)] = F::from_bool((cur[b] >> j) & 1 == 1);
                    dst[sibling_bit(b, j)] = F::from_bool((sib[b] >> j) & 1 == 1);
                }
            }
        }
        RowMajorMatrix::new(values, NUM_COLS)
    }
}

impl<F: PrimeField64> BaseAir<F> for EconSmtPathAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn preprocessed_width(&self) -> usize {
        self.preprocessed_width_()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let w = self.preprocessed_width_();
        let rows = self.num_rows();
        let mut values = F::zero_vec(rows * w);
        for (p, key) in self.keys.iter().enumerate() {
            for i in 0..SMT_HEIGHT {
                let d = F::from_bool(direction(key, i) == 1);
                for half in 0..2 {
                    let r = p * ROWS_PER_PATH + 2 * i + half;
                    let row = &mut values[r * w..(r + 1) * w];
                    row[PRE_IS_A] = F::from_bool(half == 0);
                    row[PRE_DIRECTION] = d;
                    row[PRE_PATH_START] = F::from_bool(i == 0 && half == 0);
                    row[PRE_PATH_END] = F::from_bool(i == SMT_HEIGHT - 1 && half == 1);
                    row[PRE_PATH_SEL + p] = F::ONE;
                }
            }
        }
        Some(RowMajorMatrix::new(values, w))
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        let mut cols: Vec<usize> = (OFF_INPUTS..OFF_INPUTS + 512).collect();
        cols.extend(OFF_CV..OFF_CV + 256);
        cols.extend(OFF_COUNTER_LOW..OFF_COUNTER_LOW + 32);
        cols.extend(OFF_COUNTER_HI..OFF_COUNTER_HI + 32);
        cols.extend(OFF_BLOCK_LEN..OFF_BLOCK_LEN + 32);
        cols.extend(OFF_FLAGS..OFF_FLAGS + 32);
        cols.extend(OFF_CURRENT..OFF_CURRENT + 256);
        cols
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }

    fn num_public_values(&self) -> usize {
        self.keys.len() * PUBLIC_VALUES_PER_PATH
    }
}

impl<AB: AirBuilder> Air<AB> for EconSmtPathAir
where
    AB::F: PrimeField64,
{
    fn eval(&self, builder: &mut AB) {
        // Every row is one BLAKE3 compression.
        {
            let mut sub = SubAirBuilder::<AB, Blake3Air, AB::F>::new(builder, 0..NUM_BLAKE3_COLS);
            Blake3Air {}.eval(&mut sub);
        }

        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let pre = builder.preprocessed().clone();
        let pl = pre.current_slice();
        let is_a: AB::Expr = pl[PRE_IS_A].into();
        let d: AB::Expr = pl[PRE_DIRECTION].into();
        let is_start: AB::Expr = pl[PRE_PATH_START].into();
        let is_end: AB::Expr = pl[PRE_PATH_END].into();
        let path_sel: Vec<AB::Expr> = (0..self.keys.len()).map(|p| pl[PRE_PATH_SEL + p].into()).collect();
        let pvs: Vec<AB::Expr> = builder.public_values().iter().map(|&v| v.into()).collect();
        let is_b = AB::Expr::ONE - is_a.clone();

        let bit_const = |v: u32, k: usize| AB::Expr::from_bool((v >> k) & 1 == 1);
        // The left and right 32-byte operands of this level, as the key bit selects them.
        let left = |b: usize, j: usize| -> AB::Expr {
            let cur: AB::Expr = local[current_bit(b, j)].into();
            let sib: AB::Expr = local[sibling_bit(b, j)].into();
            cur.clone() + d.clone() * (sib - cur)
        };
        let right = |b: usize, j: usize| -> AB::Expr {
            let cur: AB::Expr = local[current_bit(b, j)].into();
            let sib: AB::Expr = local[sibling_bit(b, j)].into();
            sib.clone() + d.clone() * (cur - sib)
        };

        // --- Row A: the first compression of `econ_node(left, right)`.
        // Operand bits are booleans (the message bits are, by Blake3Air, but the
        // selection only forces the chosen operand's bits to be).
        for b in 0..32 {
            for j in 0..8 {
                let cur: AB::Expr = local[current_bit(b, j)].into();
                let sib: AB::Expr = local[sibling_bit(b, j)].into();
                builder.assert_zero(is_a.clone() * cur.bool_check());
                builder.assert_zero(is_a.clone() * sib.bool_check());
            }
        }
        // Chaining value = IV; counter = 0; block_len = 64; flags = CHUNK_START.
        for w in 0..8 {
            for k in 0..32 {
                let cv: AB::Expr = local[cv_bit(w, k)].into();
                builder.assert_zero(is_a.clone() * (cv - bit_const(IV[w], k)));
            }
        }
        for k in 0..32 {
            let lo: AB::Expr = local[OFF_COUNTER_LOW + k].into();
            let hi: AB::Expr = local[OFF_COUNTER_HI + k].into();
            let len: AB::Expr = local[OFF_BLOCK_LEN + k].into();
            let flags: AB::Expr = local[OFF_FLAGS + k].into();
            builder.assert_zero(is_a.clone() * lo);
            builder.assert_zero(is_a.clone() * hi);
            builder.assert_zero(is_a.clone() * (len - bit_const(64, k)));
            builder.assert_zero(is_a.clone() * (flags - bit_const(CHUNK_START, k)));
        }
        // Message block 0 = tag ‖ 0x00 ‖ left ‖ right[0..7].
        for b in 0..64 {
            for j in 0..8 {
                let m: AB::Expr = local[input_bit(b, j)].into();
                let expected = if b < 24 {
                    AB::Expr::from_bool((TAG_ECONOMIC_SMT_NODE[b] >> j) & 1 == 1)
                } else if b < PREFIX_LEN {
                    AB::Expr::ZERO
                } else if b < PREFIX_LEN + 32 {
                    left(b - PREFIX_LEN, j)
                } else {
                    right(b - PREFIX_LEN - 32, j)
                };
                builder.assert_zero(is_a.clone() * (m - expected));
            }
        }

        // --- Row A → row B: the second compression. Row A is never the last
        // row, so no transition filter is needed.
        for w in 0..8 {
            for k in 0..32 {
                let cv_next: AB::Expr = next[cv_bit(w, k)].into();
                let out: AB::Expr = local[out_bit(w, k)].into();
                builder.assert_zero(is_a.clone() * (cv_next - out));
            }
        }
        for k in 0..32 {
            let lo: AB::Expr = next[OFF_COUNTER_LOW + k].into();
            let hi: AB::Expr = next[OFF_COUNTER_HI + k].into();
            let len: AB::Expr = next[OFF_BLOCK_LEN + k].into();
            let flags: AB::Expr = next[OFF_FLAGS + k].into();
            builder.assert_zero(is_a.clone() * lo);
            builder.assert_zero(is_a.clone() * hi);
            builder.assert_zero(is_a.clone() * (len - bit_const(TAIL_LEN as u32, k)));
            builder.assert_zero(is_a.clone() * (flags - bit_const(CHUNK_END | ROOT, k)));
        }
        // Message block 1 = right[7..32] ‖ zero padding.
        for b in 0..64 {
            for j in 0..8 {
                let m: AB::Expr = next[input_bit(b, j)].into();
                let expected = if b < TAIL_LEN { right(64 - PREFIX_LEN - 32 + b, j) } else { AB::Expr::ZERO };
                builder.assert_zero(is_a.clone() * (m - expected));
            }
        }

        // --- Row B → next level's row A: the node becomes `current`, except at
        // the end of a path.
        let carry = is_b.clone() * (AB::Expr::ONE - is_end.clone());
        for w in 0..8 {
            for k in 0..32 {
                let cur_next: AB::Expr = next[OFF_CURRENT + 32 * w + k].into();
                let out: AB::Expr = local[out_bit(w, k)].into();
                builder.assert_zero(carry.clone() * (cur_next - out));
            }
        }

        // --- Boundaries: the first `current` is the leaf, the last output the
        // root, per path, as u16 limbs.
        for (p, sel) in path_sel.iter().enumerate() {
            let base = p * PUBLIC_VALUES_PER_PATH;
            for w in 0..8 {
                for half in 0..2 {
                    let bits = half * 16..half * 16 + 16;
                    let leaf_limb: AB::Expr = pack_bits_le(bits.clone().map(|k| local[OFF_CURRENT + 32 * w + k]));
                    let root_limb: AB::Expr = pack_bits_le(bits.map(|k| local[out_bit(w, k)]));
                    builder.assert_zero(is_start.clone() * sel.clone() * (leaf_limb - pvs[base + 2 * w + half].clone()));
                    builder.assert_zero(is_end.clone() * sel.clone() * (root_limb - pvs[base + 16 + 2 * w + half].clone()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_matrix::Matrix;
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    fn random_path(rng: &mut SmallRng) -> PathWitness {
        let mut key = [0u8; 32];
        let mut leaf = [0u8; 32];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut leaf);
        let mut siblings = Box::new([[0u8; 32]; SMT_HEIGHT]);
        for s in siblings.iter_mut() {
            rng.fill_bytes(s);
        }
        PathWitness { key, leaf, siblings }
    }

    #[test]
    fn the_two_compressions_are_econ_node() {
        let mut rng = SmallRng::seed_from_u64(7);
        for _ in 0..64 {
            let mut l = [0u8; 32];
            let mut r = [0u8; 32];
            rng.fill_bytes(&mut l);
            rng.fill_bytes(&mut r);
            let (_, node) = node_compressions(&l, &r);
            assert_eq!(node, econ_node_reference(&l, &r));
        }
    }

    #[test]
    fn the_trace_rows_output_the_node() {
        type F = p3_koala_bear::KoalaBear;
        let mut rng = SmallRng::seed_from_u64(11);
        let path = random_path(&mut rng);
        let air = EconSmtPathAir::new(vec![path.key]);
        let trace = air.generate_trace::<F>(&[path.clone()], 0);
        assert_eq!(trace.height(), ROWS_PER_PATH);
        // The last row B's output is the root.
        let last = trace.row_slice(ROWS_PER_PATH - 1).unwrap();
        let mut root = [0u8; 32];
        for b in 0..32 {
            for j in 0..8 {
                let bit = last[out_bit(b / 4, 8 * (b % 4) + j)];
                if bit == F::ONE {
                    root[b] |= 1 << j;
                }
            }
        }
        assert_eq!(root, path.root());
    }

    #[test]
    fn the_constraints_hold_on_an_honest_trace_and_fail_on_a_wrong_leaf_or_a_changed_sibling() {
        type F = p3_koala_bear::KoalaBear;
        let mut rng = SmallRng::seed_from_u64(3);
        let paths = vec![random_path(&mut rng), random_path(&mut rng)];
        let air = EconSmtPathAir::new(paths.iter().map(|p| p.key).collect());
        let trace = air.generate_trace::<F>(&paths, 0);
        let pvs = public_values::<F>(&paths);
        p3_air::check_constraints(&air, &trace, &pvs);

        // A prover who presents the right root for a different leaf fails the
        // leaf boundary.
        let mut wrong = pvs.clone();
        wrong[0] += F::ONE;
        let result = std::panic::catch_unwind(|| p3_air::check_constraints(&air, &trace, &wrong));
        assert!(result.is_err(), "a wrong leaf public value must not satisfy the constraints");

        // A sibling changed after hashing fails the message binding of its row.
        let mut tampered = trace.clone();
        let row = ROWS_PER_PATH + 2 * 100; // path 1, level 100, row A
        let col = sibling_bit(5, 3);
        tampered.values[row * NUM_COLS + col] = F::ONE - tampered.values[row * NUM_COLS + col];
        let result = std::panic::catch_unwind(|| p3_air::check_constraints(&air, &tampered, &pvs));
        assert!(result.is_err(), "a changed sibling must not satisfy the constraints");
    }
}
