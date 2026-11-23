//! The `BLAKE3` glue to Flock's reduction ([`flock`]), over the one commitment. Scratch research port.
//!
//! A `BLAKE3` instruction is one BLAKE3 compression. Flock proves every instance of the run at once: its packed witness,
//! `2^14` bits (`2^8` words) per instance, is the committed column `q_flock`, laid out slot-major (word `s` of
//! instance `j` at `s * 2^tau + j`, `2^tau` the `BLAKE3` table's height), so each 64-bit word the VM reads or writes
//! is one of its slots, a column block like `q_keccak`'s. The `BLAKE3` table commits no value limb of its own: a claim
//! on one is a claim on its slot of `q_flock` (`verifier::layout::qflock_slot`). Flock's reduction leaves the 64 bit
//! slices of its witness at one point, which ring switching binds in the one opening.

use flock::hash::{Blake2sSetup, Compression, SliceClaim, blake2s_compress, generate_witness_with_ab_packed_and_lincheck};
use pcs::RingSwitchOpen;
use primitives::field::{F64, F128};
use primitives::transcript::ProverState;
use verifier::layout::QFLOCK_SLOT_BITS;

/// The cells a `BLAKE3` row accesses, in flush order (`verifier::layout`'s): the four message cells, the chaining
/// value's two, the output's two, then the metadata cell, as (offset operand, step from it). The operands are in
/// bytecode slot order: `m0..m3`, `cv`, `out`, `md`.
pub(crate) const CELLS: [(usize, u32); 9] = [(0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (4, 1), (5, 0), (5, 1), (6, 0)];
/// Where the two output cells sit in [`CELLS`].
pub(crate) const OUT_CELLS: [usize; 2] = [6, 7];

fn words(limb: u64) -> [u32; 2] {
    [limb as u32, (limb >> 32) as u32]
}

/// The compression a `BLAKE3` instruction applies, from the values of its cells in [`CELLS`] order (the output cells
/// ignored): a cell's two limbs are four little-endian words.
pub(crate) fn compression(cells: &[F128; 9]) -> Compression {
    let mut m = [0u32; 16];
    for k in 0..4 {
        let [a, b] = words(cells[k].c0);
        let [c, d] = words(cells[k].c1);
        m[4 * k..4 * k + 4].copy_from_slice(&[a, b, c, d]);
    }
    let mut cv = [0u32; 8];
    for k in 0..2 {
        let [a, b] = words(cells[4 + k].c0);
        let [c, d] = words(cells[4 + k].c1);
        cv[4 * k..4 * k + 4].copy_from_slice(&[a, b, c, d]);
    }
    let md = cells[8];
    let [block_len, flags] = words(md.c1);
    (cv, m, md.c0, block_len, flags)
}

/// The two cells a compression writes: the new chaining value.
pub(crate) fn output(c: &Compression) -> [F128; 2] {
    let h = blake2s_compress(&c.0, &c.1, c.2, c.3, c.4);
    let limb = |k: usize| h[2 * k] as u64 | (h[2 * k + 1] as u64) << 32;
    [F128::new(limb(0), limb(1)), F128::new(limb(2), limb(3))]
}

/// Flock's witness of the run, kept from the build: its packed `z`, `A z` and `B z`, and the lincheck's stripes.
pub(crate) struct Reduction {
    n_blocks: usize,
    z_packed: Vec<u64>,
    a_packed: Vec<u64>,
    b_packed: Vec<u64>,
    z_lincheck: Vec<u8>,
}

impl Reduction {
    /// Run Flock's zerocheck and lincheck, and return its 64 slices' claim as a ring-switched claim on `q_flock`, at
    /// `offset` of the stack. Its point is over the instance-major word index (word bits low); `q_flock` is committed
    /// slot-major, so the two halves of the point trade places, as the verifier's do.
    pub(crate) fn prove(&self, ps: &mut ProverState, offset: usize) -> RingSwitchOpen {
        let claim: SliceClaim = Blake2sSetup::new(self.n_blocks).prove_reduction_precomputed(
            &self.z_packed,
            &self.a_packed,
            &self.b_packed,
            &self.z_lincheck,
            ps,
        );
        let point = &claim.suffix_point;
        RingSwitchOpen {
            offset,
            points: vec![[&point[QFLOCK_SLOT_BITS..], &point[..QFLOCK_SLOT_BITS]].concat()],
        }
    }
}

/// Build Flock's witness of `blocks`, padded to `window.len() >> 8` instances with its padding instance, and write it
/// slot-major over `window`, `q_flock`.
pub(crate) fn place(blocks: &[Compression], window: &mut [F64]) -> Reduction {
    let n = window.len() >> QFLOCK_SLOT_BITS;
    assert!(n.is_power_of_two() && blocks.len() <= n, "q_flock holds every instance");
    let (z_packed, a_packed, b_packed, z_lincheck) =
        generate_witness_with_ab_packed_and_lincheck(blocks, n.trailing_zeros() as usize);
    let slots = 1 << QFLOCK_SLOT_BITS;
    assert_eq!(z_packed.len(), slots * n);
    parallel::fill(window, |i| F64(z_packed[(i % n) * slots + i / n]));
    Reduction {
        n_blocks: n,
        z_packed,
        a_packed,
        b_packed,
        z_lincheck,
    }
}
