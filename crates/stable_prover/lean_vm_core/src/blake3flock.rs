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
/// value's two, the output's two, the metadata cell, then the X, Y and W pairs, as (offset operand, step from it). The
/// operands are in bytecode slot order: `m0..m3`, `cv`, `out`, `md`, `x`, `y`, `w`.
pub(crate) const N_CELLS: usize = 15;
pub(crate) const N_OPERANDS: usize = 10;
#[rustfmt::skip]
pub(crate) const CELLS: [(usize, u32); N_CELLS] = [
    (0, 0), (1, 0), (2, 0), (3, 0), (4, 0), (4, 1), (5, 0), (5, 1), (6, 0), (7, 0), (7, 1), (8, 0), (8, 1), (9, 0), (9, 1),
];
/// Where the two output cells sit in [`CELLS`].
pub(crate) const OUT_CELLS: [usize; 2] = [6, 7];

fn words(limb: u64) -> [u32; 2] {
    [limb as u32, (limb >> 32) as u32]
}

/// The compression a `BLAKE3` instruction applies, from the values of its cells in [`CELLS`] order (the output cells
/// ignored): a cell's two limbs are four little-endian words.
pub(crate) fn compression(cells: &[F128; N_CELLS]) -> Compression {
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
    let mut xyw = [0u32; 24];
    for k in 0..6 {
        let [a, b] = words(cells[9 + k].c0);
        let [c, d] = words(cells[9 + k].c1);
        xyw[4 * k..4 * k + 4].copy_from_slice(&[a, b, c, d]);
    }
    (cv, m, md.c0, block_len, flags, xyw)
}

/// The operands of a `BLAKE3` instruction, in bytecode slot order.
pub(crate) fn operands(op: &crate::cpu::Op) -> [u32; N_OPERANDS] {
    match *op {
        crate::cpu::Op::Blake3 { m, cv, out, md, x, y, w } => [m[0], m[1], m[2], m[3], cv, out, md, x, y, w],
        op => unreachable!("not a BLAKE3: {op:?}"),
    }
}

/// The two cells a compression writes: the new chaining value.
pub(crate) fn output(c: &Compression) -> [F128; 2] {
    let h = blake2s_compress(&c.0, &flock::hash::effective_message(&c.1, &c.5), c.2, c.3, c.4);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes `formal/Statement/Blake3Vectors.lean` (`LEAN_BLAKE3_VECTORS`, the path): the `BLAKE3` instruction's
    /// compressions of some cells, as [`compression`] and [`output`] compute them, for the Lean transcription
    /// (`Statement/LeanIsa.lean`'s `Blake3CellsRelation`) to check, cell by cell.
    #[test]
    #[ignore = "writes the Lean vectors: LEAN_BLAKE3_VECTORS=<path>"]
    fn write_lean_blake3_vectors() {
        use std::fmt::Write;
        let path = std::env::var("LEAN_BLAKE3_VECTORS").expect("LEAN_BLAKE3_VECTORS: where to write the Lean vectors");
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let iv = flock::hash::param_iv();
        let iv_cell = |k: usize| {
            let limb = |i: usize| iv[2 * i] as u64 | (iv[2 * i + 1] as u64) << 32;
            F128::new(limb(2 * k), limb(2 * k + 1))
        };
        let hex = |cells: &[F128]| {
            cells.iter().flat_map(|c| [c.c0.to_le_bytes(), c.c1.to_le_bytes()].concat()).map(|x| format!("{x:02x}")).collect::<String>()
        };
        let mut out = String::from(
            "import Statement.VaultStep\n\n/-!\n# Research build: the `BLAKE3` instruction's vectors, from the Rust\n\n\
             Generated by `write_lean_blake3_vectors` (`crates/stable_prover/lean_vm_core/src/blake3flock.rs`); not edited. \
             Compressions of the cells a `BLAKE3` reads, as the executor computes them (`compression`, `output`): a \
             one-block hash with no placed input (the IV, counter 0, length 64, flags `CHUNK_START | CHUNK_END | ROOT`), \
             one with only the placed inputs, and random cells. Each `#guard` checks `Blake3CellsRelation` and the output \
             cells against them, as limbs. A plain file, not a module, so the guards may run what it imports.\n-/\n\n\
             namespace LeanVM.Semantics.Blake3.Vectors\n\nopen LeanVM.Parameters LeanVM.Semantics LeanVM.Vault\n\n\
             /-- A hex string's bytes. -/\ndef hexBytes (s : String) : List UInt8 :=\n  \
             let d := fun (c : Char) ↦ if c.isDigit then c.toNat - 48 else c.toNat - 87\n  \
             let cs := s.toList\n  (List.range (cs.length / 2)).map fun i ↦ (16 * d (cs.getD (2 * i) '0') + d (cs.getD (2 * i + 1) '0')).toUInt8\n\n\
             /-- Cell `c` of cells written as their limbs' little-endian bytes, 16 per cell. -/\n\
             def cellAt (s : String) (c : ℕ) : E := cell16 ((hexBytes s).drop (16 * c))\n\n\
             /-- A cell's two limbs, which `K`'s equality compares. -/\ndef limbs (x : E) : K × K := (x.limb 0, x.limb 1)\n\n",
        );
        for n in 0..6 {
            let mut cells: [F128; N_CELLS] = std::array::from_fn(|_| F128::new(next(), next()));
            if n == 0 || n == 1 {
                cells[4] = iv_cell(0);
                cells[5] = iv_cell(1);
                cells[8] = F128::new(0, 64 | (1 | 2 | 8) << 32);
            }
            if n == 0 {
                cells[9..].fill(F128::ZERO);
            }
            if n == 1 {
                cells[..4].fill(F128::ZERO);
            }
            for c in OUT_CELLS {
                cells[c] = F128::ZERO;
            }
            let h = output(&compression(&cells));
            let input: Vec<F128> = (0..N_CELLS).filter(|c| !OUT_CELLS.contains(c)).map(|c| cells[c]).collect();
            writeln!(
                out,
                "def input{n} : Fin 13 → E := fun c ↦ cellAt \"{}\" c.val\n\
                 def output{n} : Fin 13 → E := fun c ↦ cellAt \"{}\" c.val\n\
                 #guard limbs (chainCell (compressCells input{n}) 0) == limbs (output{n} 0)\n\
                 #guard limbs (chainCell (compressCells input{n}) 1) == limbs (output{n} 1)\n\
                 #guard decide (Blake3CellsRelation input{n} output{n})\n\
                 #guard !decide (Blake3CellsRelation input{n} (fun c ↦ if c = 1 then output{n} 0 else output{n} c))\n",
                hex(&input),
                hex(&h),
            )
            .unwrap();
            if n == 0 {
                // The one-block hash of the message is BLAKE3's of those 64 bytes: the vault step's `blake3`.
                let msg: Vec<u8> = cells[..4].iter().flat_map(|c| [c.c0.to_le_bytes(), c.c1.to_le_bytes()].concat()).collect();
                writeln!(
                    out,
                    "#guard blake3 ((hexBytes \"{}\")) == wordBytes (compressCells input0).toList\n",
                    msg.iter().map(|x| format!("{x:02x}")).collect::<String>()
                )
                .unwrap();
            }
        }
        out.push_str("end LeanVM.Semantics.Blake3.Vectors\n");
        std::fs::write(path, out).unwrap();
    }
}
