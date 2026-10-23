// SPDX-License-Identifier: MIT OR Apache-2.0

//! The economic SMT authentication path as a Plonky3 AIR.
//!
//! `R_econ` is a 256-level sparse Merkle tree whose leaves are
//! `econ_leaf(key, value) = BLAKE3(tag ‖ 0x00 ‖ key ‖ value)` with the 24-byte
//! tag `DSM/economic-smt-leaf/v1`, and whose internal nodes are
//! `econ_node(l, r) = BLAKE3(tag ‖ 0x00 ‖ l ‖ r)` with the 24-byte tag
//! `DSM/economic-smt-node/v1` (`dsm::economic::tree`). Either message is 89
//! bytes, so one hash is exactly two BLAKE3 compressions in one chunk: the
//! first over bytes `0..64` with the IV as chaining value and `CHUNK_START`,
//! the second over bytes `64..89` with the first's output as chaining value
//! and `CHUNK_END | ROOT`. The hash is the first eight output words of the
//! second compression.
//!
//! One trace row is one compression, proven by [`Blake3Air`] as a sub-AIR over
//! the first `NUM_BLAKE3_COLS` columns. Two rows make one hash. A path is the
//! leaf hash followed by 256 node hashes, 514 rows, folded leaf-to-root exactly
//! as `root_from_path` folds it. The columns after the BLAKE3 block carry the
//! hash's two operands as bits, `current` and `sibling`, and the constraints
//! bind:
//!
//! - the leaf hash's message to `leaf tag ‖ 0x00 ‖ key ‖ value`, key in
//!   `current` and value in `sibling`, both tied to the path's public values;
//! - a node hash's message to `node tag ‖ 0x00 ‖ left ‖ right` where
//!   `(left, right)` is `(current, sibling)` when the key bit is 0 and
//!   `(sibling, current)` when it is 1 — the key bit is a preprocessed column,
//!   fixed by the verifier from the key, never chosen by the prover;
//! - the second row's chaining value to the first row's output, and its
//!   message to the tail of `right`;
//! - the next hash's `current` to the previous hash's output;
//! - the last output of each path to the root public values.
//!
//! The statement proven for each path is: `root = fold(econ_leaf(key, value),
//! siblings)`, with `key`, `value` and `root` public and the siblings private.
//!
//! The trace height is a power of two: the rows past the last path are copies
//! of its final compression, so Blake3Air holds on them, with every selector
//! off so no other constraint reads them.
//!
//! A proof is over `N` paths with one key each, which is the shape of a
//! mutation: the pre-state path and the post-state path of one leaf share a
//! key and siblings and differ in the value. A leaf that is absent on one side
//! of a mutation (an insertion or a removal) is not covered: its leaf node is
//! the zero digest, not a hash.

use core::mem::offset_of;

use p3_air::utils::pack_bits_le;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_blake3_air::{Blake3Air, Blake3Cols, Blake3CompressionInput, NUM_BLAKE3_COLS};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SubAirBuilder;
use rand::Rng;
use rand::rngs::SmallRng;

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
/// Rows of the leaf hash: two compressions.
pub const LEAF_ROWS: usize = 2;
/// Rows per path: the leaf hash, then two compressions per level.
pub const ROWS_PER_PATH: usize = LEAF_ROWS + 2 * SMT_HEIGHT;
/// Columns after the BLAKE3 block: `current` (256 bits) then `sibling` (256 bits).
pub const NUM_EXTRA_COLS: usize = 512;
/// Trace width.
pub const NUM_COLS: usize = NUM_BLAKE3_COLS + NUM_EXTRA_COLS;
/// Public values per path: key, value and root, each as 16 u16 limbs.
pub const PUBLIC_VALUES_PER_PATH: usize = 48;

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

/// Bit `k` of `v`, as 0 or 1.
#[inline]
const fn bit_of(v: u32, k: usize) -> u8 {
    ((v >> k) & 1) as u8
}

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
    core::array::from_fn(|w| {
        u32::from_le_bytes([
            block[4 * w],
            block[4 * w + 1],
            block[4 * w + 2],
            block[4 * w + 3],
        ])
    })
}

fn digest_words(d: &[u8; 32]) -> [u32; 8] {
    core::array::from_fn(|w| {
        u32::from_le_bytes([d[4 * w], d[4 * w + 1], d[4 * w + 2], d[4 * w + 3]])
    })
}

fn digest_bytes(words: &[u32]) -> [u8; 32] {
    core::array::from_fn(|i| words[i / 4].to_le_bytes()[i % 4])
}

/// A hook that may alter one compression after it is built and before it is
/// compressed: `(0, first)` or `(1, second)`. Production passes none; tests use
/// it to build a trace that is honest everywhere except one link.
type Tweak<'a> = &'a dyn Fn(usize, &mut Blake3CompressionInput);

/// The two compressions of `H_dom(tag, left ‖ right)`, in order, and the digest.
pub fn pair_compressions(
    tag: &[u8; 24],
    left: &[u8; 32],
    right: &[u8; 32],
) -> ([Blake3CompressionInput; 2], [u8; 32]) {
    pair_compressions_with(tag, left, right, &|_, _| {})
}

fn pair_compressions_with(
    tag: &[u8; 24],
    left: &[u8; 32],
    right: &[u8; 32],
    tweak: Tweak<'_>,
) -> ([Blake3CompressionInput; 2], [u8; 32]) {
    let mut msg = [0u8; NODE_MSG_LEN];
    msg[..24].copy_from_slice(tag);
    msg[24] = 0;
    msg[PREFIX_LEN..PREFIX_LEN + 32].copy_from_slice(left);
    msg[PREFIX_LEN + 32..].copy_from_slice(right);
    let mut first = Blake3CompressionInput {
        chaining_value: IV,
        block: words_le(&msg[..64]),
        counter: 0,
        block_len: 64,
        flags: CHUNK_START,
    };
    tweak(0, &mut first);
    let out_a = compress(&first);
    let mut second = Blake3CompressionInput {
        chaining_value: core::array::from_fn(|i| out_a[i]),
        block: words_le(&msg[64..]),
        counter: 0,
        block_len: TAIL_LEN as u32,
        flags: CHUNK_END | ROOT,
    };
    tweak(1, &mut second);
    let out_b = compress(&second);
    ([first, second], digest_bytes(&out_b))
}

/// The two compressions of `econ_node(left, right)`, in order, and the node.
pub fn node_compressions(
    left: &[u8; 32],
    right: &[u8; 32],
) -> ([Blake3CompressionInput; 2], [u8; 32]) {
    pair_compressions(TAG_ECONOMIC_SMT_NODE, left, right)
}

/// The two compressions of `econ_leaf(key, value)`, in order, and the leaf.
pub fn leaf_compressions(
    key: &[u8; 32],
    value: &[u8; 32],
) -> ([Blake3CompressionInput; 2], [u8; 32]) {
    pair_compressions(TAG_ECONOMIC_SMT_LEAF, key, value)
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
pub fn root_from_path_reference(
    key: &[u8; 32],
    leaf: &[u8; 32],
    siblings: &[[u8; 32]; SMT_HEIGHT],
) -> [u8; 32] {
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

/// One leaf-to-root path: what the prover knows. `key`, `value` and the root
/// it folds to are the statement; the siblings are private.
#[derive(Clone)]
pub struct PathWitness {
    pub key: [u8; 32],
    pub value: [u8; 32],
    pub siblings: Box<[[u8; 32]; SMT_HEIGHT]>,
}

impl PathWitness {
    /// `econ_leaf(key, value)`.
    pub fn leaf(&self) -> [u8; 32] {
        econ_leaf_reference(&self.key, &self.value)
    }

    /// The root this path folds to.
    pub fn root(&self) -> [u8; 32] {
        root_from_path_reference(&self.key, &self.leaf(), &self.siblings)
    }
}

fn random_digest(rng: &mut SmallRng) -> [u8; 32] {
    core::array::from_fn(|_| rng.next_u32() as u8)
}

/// A random witness. A proof's cost does not depend on the values.
pub fn random_witness(rng: &mut SmallRng) -> PathWitness {
    let key = random_digest(rng);
    let value = random_digest(rng);
    let siblings = Box::new(core::array::from_fn(|_| random_digest(rng)));
    PathWitness {
        key,
        value,
        siblings,
    }
}

/// A digest as sixteen u16 limbs, low limb first per word.
pub fn digest_limbs<F: PrimeField64>(d: &[u8; 32]) -> [F; 16] {
    let words = digest_words(d);
    core::array::from_fn(|i| {
        let w = words[i / 2];
        if i % 2 == 0 {
            F::from_u16(w as u16)
        } else {
            F::from_u16((w >> 16) as u16)
        }
    })
}

/// The public values for `paths`: per path, key limbs, value limbs, root limbs.
pub fn public_values<F: PrimeField64>(paths: &[PathWitness]) -> Vec<F> {
    let mut pvs = Vec::with_capacity(paths.len() * PUBLIC_VALUES_PER_PATH);
    for p in paths {
        pvs.extend_from_slice(&digest_limbs::<F>(&p.key));
        pvs.extend_from_slice(&digest_limbs::<F>(&p.value));
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

/// Preprocessed columns, all fixed by the verifier from the keys:
/// `is_a` and `is_b` (first and second compression of a hash, both zero on the
/// padding rows), `is_leaf` (either row of the leaf hash), `is_leaf_a` (its
/// first row), `direction` (the key bit a node level consumes; zero on the leaf
/// rows), `carry` (the second row of a hash whose output feeds the next hash),
/// `is_end` (the last row of a path), then one selector per path.
const PRE_IS_A: usize = 0;
const PRE_IS_B: usize = 1;
const PRE_IS_LEAF: usize = 2;
const PRE_IS_LEAF_A: usize = 3;
const PRE_DIRECTION: usize = 4;
const PRE_CARRY: usize = 5;
const PRE_IS_END: usize = 6;
const PRE_PATH_SEL: usize = 7;

// ---------------------------------------------------------------------------
// The AIR.
// ---------------------------------------------------------------------------

/// The economic SMT path AIR over `keys.len()` paths, one key each. The keys
/// are the verifier's: they fix the preprocessed trace.
pub struct EconSmtPathAir {
    pub keys: Vec<[u8; 32]>,
}

impl EconSmtPathAir {
    pub fn new(keys: Vec<[u8; 32]>) -> Self {
        assert!(!keys.is_empty(), "at least one path");
        Self { keys }
    }

    pub fn num_paths(&self) -> usize {
        self.keys.len()
    }

    /// Rows that carry a path.
    pub fn real_rows(&self) -> usize {
        self.keys.len() * ROWS_PER_PATH
    }

    /// The trace height: the path rows, padded to a power of two.
    pub fn num_rows(&self) -> usize {
        self.real_rows().next_power_of_two()
    }

    fn preprocessed_width_(&self) -> usize {
        PRE_PATH_SEL + self.keys.len()
    }

    /// The main trace for `paths`, whose keys must be this AIR's keys in order.
    pub fn generate_trace<F: PrimeField64>(
        &self,
        paths: &[PathWitness],
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        self.generate_trace_with(paths, extra_capacity_bits, &|_, _| {})
            .0
    }

    /// The trace, with `tweak(row, compression)` applied to the compression of
    /// each trace row before it is compressed, and the root each path then folds
    /// to. With no alteration the roots are the witnesses'.
    fn generate_trace_with<F: PrimeField64>(
        &self,
        paths: &[PathWitness],
        extra_capacity_bits: usize,
        tweak: Tweak<'_>,
    ) -> (RowMajorMatrix<F>, Vec<[u8; 32]>) {
        assert_eq!(paths.len(), self.keys.len());
        for (p, k) in paths.iter().zip(&self.keys) {
            assert_eq!(&p.key, k, "path key is not the AIR's key");
        }
        let rows = self.num_rows();
        let mut inputs: Vec<Blake3CompressionInput> = Vec::with_capacity(rows);
        // The two operands of a hash on its first row; nothing on its second or on padding.
        let mut extras: Vec<Option<([u8; 32], [u8; 32])>> = Vec::with_capacity(rows);
        let mut roots = Vec::with_capacity(paths.len());
        for p in paths {
            let base = inputs.len();
            let (two, leaf) =
                pair_compressions_with(TAG_ECONOMIC_SMT_LEAF, &p.key, &p.value, &|which, input| {
                    tweak(base + which, input)
                });
            inputs.extend(two);
            extras.push(Some((p.key, p.value)));
            extras.push(None);
            let mut current = leaf;
            for (i, sibling) in p.siblings.iter().enumerate() {
                let (left, right) = if direction(&p.key, i) == 0 {
                    (current, *sibling)
                } else {
                    (*sibling, current)
                };
                let at = inputs.len();
                let (two, node) = pair_compressions_with(
                    TAG_ECONOMIC_SMT_NODE,
                    &left,
                    &right,
                    &|which, input| tweak(at + which, input),
                );
                inputs.extend(two);
                extras.push(Some((current, *sibling)));
                extras.push(None);
                current = node;
            }
            roots.push(current);
        }
        // Padding: a copy of the last genuine compression, which Blake3Air holds on.
        let [.., last] = inputs.as_slice() else {
            panic!("a trace needs at least one path");
        };
        let filler = *last;
        while inputs.len() < rows {
            inputs.push(filler);
            extras.push(None);
        }
        let blake = p3_blake3_air::generate_trace_rows_with_inputs::<F>(inputs, 0);
        let mut values = F::zero_vec((rows * NUM_COLS) << extra_capacity_bits);
        values.truncate(rows * NUM_COLS);
        for r in 0..rows {
            let dst = &mut values[r * NUM_COLS..(r + 1) * NUM_COLS];
            dst[..NUM_BLAKE3_COLS]
                .copy_from_slice(&blake.values[r * NUM_BLAKE3_COLS..(r + 1) * NUM_BLAKE3_COLS]);
            if let Some((cur, sib)) = extras[r] {
                for b in 0..32 {
                    for j in 0..8 {
                        dst[current_bit(b, j)] = F::from_u8((cur[b] >> j) & 1);
                        dst[sibling_bit(b, j)] = F::from_u8((sib[b] >> j) & 1);
                    }
                }
            }
        }
        (RowMajorMatrix::new(values, NUM_COLS), roots)
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
            for k in 0..ROWS_PER_PATH {
                let row = &mut values[(p * ROWS_PER_PATH + k) * w..(p * ROWS_PER_PATH + k + 1) * w];
                let half = k % 2;
                let is_leaf = k < LEAF_ROWS;
                let level = k.saturating_sub(LEAF_ROWS) / 2;
                row[PRE_IS_A] = F::from_bool(half == 0);
                row[PRE_IS_B] = F::from_bool(half == 1);
                row[PRE_IS_LEAF] = F::from_bool(is_leaf);
                row[PRE_IS_LEAF_A] = F::from_bool(k == 0);
                if !is_leaf {
                    row[PRE_DIRECTION] = F::from_u8(direction(key, level));
                }
                row[PRE_CARRY] = F::from_bool(half == 1 && k != ROWS_PER_PATH - 1);
                row[PRE_IS_END] = F::from_bool(k == ROWS_PER_PATH - 1);
                row[PRE_PATH_SEL + p] = F::ONE;
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
        let is_leaf: AB::Expr = pl[PRE_IS_LEAF].into();
        let is_leaf_a: AB::Expr = pl[PRE_IS_LEAF_A].into();
        let d: AB::Expr = pl[PRE_DIRECTION].into();
        let carry: AB::Expr = pl[PRE_CARRY].into();
        let is_end: AB::Expr = pl[PRE_IS_END].into();
        let path_sel: Vec<AB::Expr> = (0..self.keys.len())
            .map(|p| pl[PRE_PATH_SEL + p].into())
            .collect();
        let pvs: Vec<AB::Expr> = builder.public_values().iter().map(|&v| v.into()).collect();

        let bit_const = |v: u32, k: usize| AB::Expr::from_u8(bit_of(v, k));
        // The left and right 32-byte operands of this hash, as the key bit selects
        // them. On the leaf rows the direction is zero: `(key, value)` in order.
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

        // --- Row A: the first compression of `H_dom(tag, left ‖ right)`.
        // The operand bits need no boolean check of their own: every bit of
        // `current` and `sibling` is equated below to a message bit of row A or B
        // (the direction is a preprocessed 0 or 1, so each operand lands in
        // exactly one of `left`, `right`), and Blake3Air constrains the message
        // bits to be boolean.
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
        // Message block 0 = tag ‖ 0x00 ‖ left ‖ right[0..7], the tag the leaf's on
        // the leaf rows and the node's elsewhere.
        for b in 0..64 {
            for j in 0..8 {
                let m: AB::Expr = local[input_bit(b, j)].into();
                let expected = if b < 24 {
                    let node_bit = AB::Expr::from_u8((TAG_ECONOMIC_SMT_NODE[b] >> j) & 1);
                    let leaf_bit = AB::Expr::from_u8((TAG_ECONOMIC_SMT_LEAF[b] >> j) & 1);
                    node_bit.clone() + is_leaf.clone() * (leaf_bit - node_bit)
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
                let expected = if b < TAIL_LEN {
                    right(64 - PREFIX_LEN - 32 + b, j)
                } else {
                    AB::Expr::ZERO
                };
                builder.assert_zero(is_a.clone() * (m - expected));
            }
        }

        // --- Row B → the next hash's row A: the digest becomes `current`,
        // from the leaf hash into the first level and from each level into the
        // next; not at the end of a path, and not on the padding.
        for w in 0..8 {
            for k in 0..32 {
                let cur_next: AB::Expr = next[OFF_CURRENT + 32 * w + k].into();
                let out: AB::Expr = local[out_bit(w, k)].into();
                builder.assert_zero(carry.clone() * (cur_next - out));
            }
        }

        // --- Boundaries, per path, as u16 limbs: the leaf hash's key and value
        // are the public key and value; the last output is the public root.
        for (p, sel) in path_sel.iter().enumerate() {
            let base = p * PUBLIC_VALUES_PER_PATH;
            for w in 0..8 {
                for half in 0..2 {
                    let bits = half * 16..half * 16 + 16;
                    let key_limb: AB::Expr =
                        pack_bits_le(bits.clone().map(|k| local[OFF_CURRENT + 32 * w + k]));
                    let value_limb: AB::Expr =
                        pack_bits_le(bits.clone().map(|k| local[OFF_SIBLING + 32 * w + k]));
                    let root_limb: AB::Expr = pack_bits_le(bits.map(|k| local[out_bit(w, k)]));
                    builder.assert_zero(
                        is_leaf_a.clone()
                            * sel.clone()
                            * (key_limb - pvs[base + 2 * w + half].clone()),
                    );
                    builder.assert_zero(
                        is_leaf_a.clone()
                            * sel.clone()
                            * (value_limb - pvs[base + 16 + 2 * w + half].clone()),
                    );
                    builder.assert_zero(
                        is_end.clone()
                            * sel.clone()
                            * (root_limb - pvs[base + 32 + 2 * w + half].clone()),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;
    use rand::SeedableRng;

    type F = KoalaBear;

    fn honest(
        seed: u64,
        paths: usize,
    ) -> (EconSmtPathAir, Vec<PathWitness>, RowMajorMatrix<F>, Vec<F>) {
        let mut rng = SmallRng::seed_from_u64(seed);
        let witnesses: Vec<PathWitness> = (0..paths).map(|_| random_witness(&mut rng)).collect();
        let air = EconSmtPathAir::new(witnesses.iter().map(|p| p.key).collect());
        let trace = air.generate_trace::<F>(&witnesses, 0);
        let pvs = public_values::<F>(&witnesses);
        (air, witnesses, trace, pvs)
    }

    #[test]
    fn the_two_compressions_are_econ_node() {
        let mut rng = SmallRng::seed_from_u64(7);
        for _ in 0..64 {
            let l = random_digest(&mut rng);
            let r = random_digest(&mut rng);
            let (_, node) = node_compressions(&l, &r);
            assert_eq!(node, econ_node_reference(&l, &r));
        }
    }

    #[test]
    fn the_two_compressions_are_econ_leaf() {
        let mut rng = SmallRng::seed_from_u64(8);
        for _ in 0..64 {
            let k = random_digest(&mut rng);
            let v = random_digest(&mut rng);
            let (_, leaf) = leaf_compressions(&k, &v);
            assert_eq!(leaf, econ_leaf_reference(&k, &v));
        }
    }

    #[test]
    fn the_leaf_and_the_node_of_the_same_operands_differ() {
        let mut rng = SmallRng::seed_from_u64(9);
        let a = random_digest(&mut rng);
        let b = random_digest(&mut rng);
        assert_ne!(econ_leaf_reference(&a, &b), econ_node_reference(&a, &b));
    }

    #[test]
    fn the_trace_is_padded_to_a_power_of_two_and_its_rows_output_the_root() {
        let (air, witnesses, trace, _) = honest(11, 1);
        assert_eq!(trace.height(), 1024);
        assert_eq!(air.real_rows(), ROWS_PER_PATH);
        // The last real row B's output is the root.
        let Some(last) = trace.row_slice(ROWS_PER_PATH - 1) else {
            panic!("the last real row exists");
        };
        let root: [u8; 32] = core::array::from_fn(|b| {
            (0..8).fold(0u8, |acc, j| {
                if last[out_bit(b / 4, 8 * (b % 4) + j)] == F::ONE {
                    acc | (1 << j)
                } else {
                    acc
                }
            })
        });
        assert_eq!(root, witnesses[0].root());
    }

    #[test]
    fn the_constraints_hold_on_an_honest_trace_of_one_two_and_four_paths() {
        for paths in [1, 2, 4] {
            let (air, _, trace, pvs) = honest(3 + paths as u64, paths);
            p3_air::check_constraints(&air, &trace, &pvs);
        }
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_wrong_value_public_value_fails() {
        let (air, _, trace, mut pvs) = honest(3, 2);
        pvs[16] += F::ONE;
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_wrong_key_public_value_fails() {
        let (air, _, trace, mut pvs) = honest(3, 2);
        pvs[0] += F::ONE;
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_wrong_root_public_value_fails() {
        let (air, _, trace, mut pvs) = honest(3, 2);
        pvs[PUBLIC_VALUES_PER_PATH + 32] += F::ONE;
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_sibling_changed_after_hashing_fails() {
        let (air, _, mut trace, pvs) = honest(3, 2);
        let row = ROWS_PER_PATH + LEAF_ROWS + 2 * 100; // path 1, level 100, row A
        let col = sibling_bit(5, 3);
        trace.values[row * NUM_COLS + col] = F::ONE - trace.values[row * NUM_COLS + col];
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_value_changed_in_the_leaf_row_after_hashing_fails() {
        let (air, _, mut trace, pvs) = honest(3, 2);
        let row = ROWS_PER_PATH; // path 1, leaf hash, row A
        let col = sibling_bit(9, 1);
        trace.values[row * NUM_COLS + col] = F::ONE - trace.values[row * NUM_COLS + col];
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_leaf_not_carried_into_the_first_level_fails() {
        let (air, _, mut trace, pvs) = honest(3, 1);
        let row = LEAF_ROWS; // path 0, level 0, row A: its `current` must be the leaf
        let col = current_bit(2, 4);
        trace.values[row * NUM_COLS + col] = F::ONE - trace.values[row * NUM_COLS + col];
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    /// Public values for `paths` with the roots a (possibly altered) trace folds to.
    fn public_values_with_roots(paths: &[PathWitness], roots: &[[u8; 32]]) -> Vec<F> {
        let mut pvs = Vec::new();
        for (p, root) in paths.iter().zip(roots) {
            pvs.extend_from_slice(&digest_limbs::<F>(&p.key));
            pvs.extend_from_slice(&digest_limbs::<F>(&p.value));
            pvs.extend_from_slice(&digest_limbs::<F>(root));
        }
        pvs
    }

    /// A trace honest everywhere except the one compression `alter` changes at
    /// trace row `row`, with public values that state the root it then folds to.
    fn one_row_altered(
        row: usize,
        alter: impl Fn(&mut Blake3CompressionInput),
    ) -> (EconSmtPathAir, RowMajorMatrix<F>, Vec<F>) {
        let mut rng = SmallRng::seed_from_u64(21);
        let witnesses = vec![random_witness(&mut rng)];
        let air = EconSmtPathAir::new(vec![witnesses[0].key]);
        let (trace, roots) = air.generate_trace_with::<F>(&witnesses, 0, &|r, input| {
            if r == row {
                alter(input);
            }
        });
        let pvs = public_values_with_roots(&witnesses, &roots);
        (air, trace, pvs)
    }

    #[test]
    fn an_alteration_that_changes_nothing_is_still_an_honest_trace() {
        let (air, trace, pvs) = one_row_altered(LEAF_ROWS + 20, |_| {});
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_second_compression_not_chained_to_the_first_fails() {
        let (air, trace, pvs) =
            one_row_altered(LEAF_ROWS + 20 + 1, |input| input.chaining_value[0] ^= 1);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_first_compression_not_started_from_the_iv_fails() {
        let (air, trace, pvs) =
            one_row_altered(LEAF_ROWS + 20, |input| input.chaining_value[0] ^= 1);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_first_compression_with_other_flags_fails() {
        let (air, trace, pvs) = one_row_altered(LEAF_ROWS + 20, |input| input.flags ^= 4);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_second_compression_with_other_flags_fails() {
        let (air, trace, pvs) = one_row_altered(LEAF_ROWS + 20 + 1, |input| input.flags ^= 4);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_second_compression_with_another_length_fails() {
        let (air, trace, pvs) = one_row_altered(LEAF_ROWS + 20 + 1, |input| input.block_len -= 1);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_first_compression_with_another_length_fails() {
        let (air, trace, pvs) = one_row_altered(LEAF_ROWS + 20, |input| input.block_len = 63);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_first_compression_with_a_block_counter_fails() {
        let (air, trace, pvs) = one_row_altered(LEAF_ROWS + 20, |input| input.counter = 1);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_second_compression_with_a_block_counter_fails() {
        let (air, trace, pvs) = one_row_altered(LEAF_ROWS + 20 + 1, |input| input.counter = 1);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn another_domain_tag_fails() {
        // Word 0 of the first block is the first four bytes of the tag.
        let (air, trace, pvs) = one_row_altered(LEAF_ROWS + 20, |input| input.block[0] ^= 1);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_nonzero_separator_byte_fails() {
        // Byte 24 is the low byte of word 6.
        let (air, trace, pvs) = one_row_altered(LEAF_ROWS + 20, |input| input.block[6] ^= 1);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_right_operand_head_changed_in_the_first_block_fails() {
        // Word 15 is bytes 60..64 of the message: bytes 3..7 of the right operand.
        let (air, trace, pvs) = one_row_altered(LEAF_ROWS + 20, |input| input.block[15] ^= 1);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_right_operand_tail_changed_in_the_second_block_fails() {
        // Word 0 of the second block is message bytes 64..68: right bytes 7..11.
        let (air, trace, pvs) = one_row_altered(LEAF_ROWS + 20 + 1, |input| input.block[0] ^= 1);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_nonzero_padding_word_in_the_second_block_fails() {
        // The message is 89 bytes; word 15 of the second block is bytes 124..128.
        let (air, trace, pvs) = one_row_altered(LEAF_ROWS + 20 + 1, |input| input.block[15] ^= 1);
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_leaf_hash_not_connected_to_the_first_level_fails() {
        // Two honest paths under one key: the leaf hash of the first and the
        // levels of the second. Every row is consistent in itself; only the
        // step from the leaf hash into level 0 is broken.
        let mut rng = SmallRng::seed_from_u64(31);
        let first = random_witness(&mut rng);
        let mut second = random_witness(&mut rng);
        second.key = first.key;
        let air = EconSmtPathAir::new(vec![first.key]);
        let from_first = air.generate_trace::<F>(core::slice::from_ref(&first), 0);
        let from_second = air.generate_trace::<F>(core::slice::from_ref(&second), 0);
        let mut spliced = from_first.clone();
        for row in LEAF_ROWS..air.real_rows() {
            let range = row * NUM_COLS..(row + 1) * NUM_COLS;
            spliced.values[range.clone()].copy_from_slice(&from_second.values[range]);
        }
        let stated = PathWitness {
            key: first.key,
            value: first.value,
            siblings: second.siblings.clone(),
        };
        let pvs = public_values_with_roots(&[stated], &[second.root()]);
        p3_air::check_constraints(&air, &spliced, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_sibling_changed_in_the_second_block_after_hashing_fails() {
        let (air, _, mut trace, pvs) = {
            let (air, w, trace, pvs) = honest(3, 2);
            (air, w, trace, pvs)
        };
        let row = ROWS_PER_PATH + LEAF_ROWS + 2 * 100; // path 1, level 100, row A
        let col = sibling_bit(20, 2); // a byte of the operand the second block carries
        trace.values[row * NUM_COLS + col] = F::ONE - trace.values[row * NUM_COLS + col];
        p3_air::check_constraints(&air, &trace, &pvs);
    }

    #[test]
    #[should_panic(expected = "failed constraints")]
    fn a_trace_built_for_another_key_fails_the_verifiers_direction_bits() {
        let (_, witnesses, trace, pvs) = honest(3, 1);
        // The verifier derives its preprocessed trace from the key it was
        // given; one differing key bit moves a level's operands.
        let mut other_key = witnesses[0].key;
        other_key[0] ^= 0x80;
        let other = EconSmtPathAir::new(vec![other_key]);
        p3_air::check_constraints(&other, &trace, &pvs);
    }
}
