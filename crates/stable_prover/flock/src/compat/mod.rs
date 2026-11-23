//! What flock took from the old leanVM's `primitives` and `pcs` crates (4242200163b0), carried over to this tree's
//! field: the GF(2^8) subfield and its additive NTT for the univariate skip, the `phi_8` embedding (into `F128` here,
//! where the old tree had `F192`), bit packing and transposes, streaming stores, the BLAKE3 compression's constants,
//! and the few multilinear helpers flock calls. Scratch research port; not upstream.

pub mod bits;
pub mod gf8;
#[cfg(target_arch = "aarch64")]
pub mod neon;
pub mod ntt;
pub mod pack;
pub mod stream;
#[cfg(test)]
pub mod test_rng;

pub use gf8::F8;
use primitives::field::F128;

/// `phi_8(2^k)` for k in 0..8: the images of the GF(2^8) polynomial basis in the base field GF(2^64) (the same
/// field as the old tree's, `x^64 + x^4 + x^3 + x + 1`), so every image has `c1 == 0`.
const PHI_8_BASIS: [u64; 8] = [
    0x0000000000000001,
    0x033ce8beddc8a656,
    0x512620375ed2a108,
    0x0c9e636090aafc01,
    0xba4f3cd82801769c,
    0xba26e7904adb4a47,
    0x467698598926dc01,
    0x4418ae808b28bdd0,
];

const fn build_phi8_table() -> [F128; 256] {
    let mut table = [F128::ZERO; 256];
    let mut value = 1;
    while value < table.len() {
        let mut c0 = 0u64;
        let mut bit = 0;
        while bit < PHI_8_BASIS.len() {
            if value & (1 << bit) != 0 {
                c0 ^= PHI_8_BASIS[bit];
            }
            bit += 1;
        }
        table[value] = F128::new(c0, 0);
        value += 1;
    }
    table
}

/// The GF(2^8) subfield of the base field, as `F128` elements.
pub static PHI_8_TABLE: [F128; 256] = build_phi8_table();

#[inline]
pub fn phi8(a: F8) -> F128 {
    PHI_8_TABLE[a.0 as usize]
}

/// A vector of `len` uninitialized elements.
///
/// # Safety
///
/// The caller writes every element before reading it.
#[must_use]
#[expect(clippy::uninit_vec, reason = "the caller writes every element before reading it")]
pub unsafe fn uninit_vec<T: Copy>(len: usize) -> Vec<T> {
    let mut v = Vec::with_capacity(len);
    // SAFETY: the capacity holds `len` elements, and the caller writes each one before reading it.
    unsafe { v.set_len(len) };
    v
}

/// The BLAKE3 compression function's constants: its IV (BLAKE2s's, the SHA-256 IV), its 7 rounds and message schedule,
/// and the lanes each of a round's eight `G` calls mixes.
pub mod blake {
    pub const IV: [u32; 8] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];
    pub const ROUNDS: usize = 7;
    pub const SIGMA: [[usize; 16]; ROUNDS] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
        [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
        [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
        [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
        [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
        [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
    ];
    /// `G(a, b, c, d)` lanes: four columns, then four diagonals.
    pub const G_LANES: [[usize; 4]; 8] = [
        [0, 4, 8, 12],
        [1, 5, 9, 13],
        [2, 6, 10, 14],
        [3, 7, 11, 15],
        [0, 5, 10, 15],
        [1, 6, 11, 12],
        [2, 7, 8, 13],
        [3, 4, 9, 14],
    ];
}

/// Multilinear and univariate helpers flock uses, on `F128`.
pub mod multilinear {
    use super::PHI_8_TABLE;
    use primitives::field::F128;

    pub use primitives::multilinear::{eq_table, poly_eval};

    /// The one barycentric denominator a power-of-two `phi_8` window has, inverted: `prod_(k != 0) PHI[k]`.
    pub fn window_denominator(size: usize) -> F128 {
        PHI_8_TABLE[1..size].iter().fold(F128::ONE, |acc, &node| acc * node).inv()
    }

    /// The barycentric weights of an aligned `phi_8` window `nodes` at `p`.
    fn lagrange_weights(nodes: &[F128], p: F128) -> Vec<F128> {
        let n = nodes.len();
        debug_assert!(n.is_power_of_two() && n <= PHI_8_TABLE.len());
        debug_assert!(
            (0..n).all(|a| nodes[a] == nodes[0] + PHI_8_TABLE[a]),
            "not an aligned phi_8 window"
        );
        let denominator = window_denominator(n);
        (0..n)
            .map(|i| {
                let mut num = F128::ONE;
                for (k, &node) in nodes.iter().enumerate() {
                    if k != i {
                        num *= p + node;
                    }
                }
                num * denominator
            })
            .collect()
    }

    /// The interpolant of `values` on `nodes`, at `p`.
    pub fn lagrange_eval(nodes: &[F128], values: &[F128], p: F128) -> F128 {
        debug_assert_eq!(nodes.len(), values.len());
        lagrange_weights(nodes, p)
            .iter()
            .zip(values)
            .fold(F128::ZERO, |acc, (&w, &v)| acc + v * w)
    }

    /// The Lagrange weights of the first `2^k_skip` `phi_8` nodes at `z`.
    pub fn lagrange_weights_naive(k_skip: usize, z: F128) -> Vec<F128> {
        let ell = 1usize << k_skip;
        assert!(ell <= 256, "k_skip > 8 would exceed PHI_8_TABLE");
        lagrange_weights(&PHI_8_TABLE[..ell], z)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phi8_is_a_field_embedding() {
        for a in 0u16..256 {
            for b in 0u16..256 {
                let (fa, fb) = (F8(a as u8), F8(b as u8));
                assert_eq!(phi8(fa * fb), phi8(fa) * phi8(fb), "mul at a={a}, b={b}");
                assert_eq!(phi8(fa + fb), phi8(fa) + phi8(fb), "add at a={a}, b={b}");
            }
        }
    }
}
