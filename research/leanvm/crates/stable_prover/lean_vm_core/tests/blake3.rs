//! The `BLAKE3` instruction end to end, in this research build (leanVM 68b4844b with Flock carried over): zkDSL
//! programs that hash through it, proved by `cpu::prove` and checked by the `verifier` crate; the digests against the
//! `blake3` crate's (1.8.7); tampered proofs and a wrong digest refused.

extern crate stable_lean_vm_core as lean_vm_core;

use isa::Program;
use lean_vm_core::cpu::{ExecError, ProveError, prove, verify};
use primitives::field::F128;
use std::collections::BTreeMap;
use verifier::blake3::{IV, compress, limb};
use zkdsl_compiler::{compile, f128_literal, parse_with_replacements};

const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const ROOT: u32 = 8;

/// Four little-endian words as a memory cell, two to a limb.
fn cell(w: &[u32]) -> F128 {
    F128::new(limb(w[0], w[1]), limb(w[2], w[3]))
}

/// The metadata cell: the chunk counter, then the block length and the flags.
fn md(counter: u64, block_len: u32, flags: u32) -> F128 {
    F128::new(counter, limb(block_len, flags))
}

fn lit(v: F128) -> String {
    f128_literal(verifier::E::new(v.c0, v.c1))
}

fn words(bytes: &[u8]) -> [u32; 16] {
    std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()))
}

fn program(source: &str, constants: &[(&str, F128)]) -> Program {
    let replacements: BTreeMap<String, String> = constants.iter().map(|&(k, v)| (k.to_string(), lit(v))).collect();
    let ast = parse_with_replacements(source, &replacements).expect("parse zkDSL program");
    Program::from(compile(&ast))
}

/// One compression through the instruction, `out = blake3_compress(cv, a ‖ b, md)`, written to the public input.
const ONE: &str = r#"
from snark_lib import *

def main():
    a = StackBuf(2)
    b = StackBuf(2)
    cv = StackBuf(2)
    out = StackBuf(2)
    a[0] = A0
    a[1] = A1
    b[0] = B0
    b[1] = B1
    cv[0] = CV0
    cv[1] = CV1
    blake3(a, b, cv, MD, out)
    public = GEN ** 0
    public[1] = out[0]
    public[GEN] = out[1]
    return
"#;

/// Two compressions chained: a two-block chunk.
const TWO: &str = r#"
from snark_lib import *

def main():
    a = StackBuf(2)
    b = StackBuf(2)
    c = StackBuf(2)
    d = StackBuf(2)
    iv = StackBuf(2)
    mid = StackBuf(2)
    out = StackBuf(2)
    a[0] = A0
    a[1] = A1
    b[0] = B0
    b[1] = B1
    c[0] = C0
    c[1] = C1
    d[0] = D0
    d[1] = D1
    iv[0] = CV0
    iv[1] = CV1
    blake3(a, b, iv, MD1, mid)
    blake3(c, d, mid, MD2, out)
    public = GEN ** 0
    public[1] = out[0]
    public[GEN] = out[1]
    return
"#;

/// A chain of `N` compressions, `x_{i+1} = blake3(x_i ‖ x_i)` as one-block hashes.
const CHAIN: &str = r#"
from snark_lib import *

N = N_PLACEHOLDER

def step(x0, x1):
    x = StackBuf(2)
    x[0] = x0
    x[1] = x1
    cv = StackBuf(2)
    cv[0] = CV0
    cv[1] = CV1
    y = StackBuf(2)
    blake3(x, x, cv, MD, y)
    return y[0], y[1]

def main():
    c0 = HeapBuf(N + 1)
    c1 = HeapBuf(N + 1)
    c0[1] = X0
    c1[1] = X1
    for index in mul_range(1, GEN ** N):
        y0, y1 = step(c0[index], c1[index])
        c0[index * GEN] = y0
        c1[index * GEN] = y1
    public = GEN ** 0
    public[1] = c0[GEN ** N]
    public[GEN] = c1[GEN ** N]
    return
"#;

fn digest_cells(h: &[u32; 8]) -> [F128; 2] {
    [cell(&h[..4]), cell(&h[4..])]
}

/// Prove, verify, and check the proof is of `n_blake3` instructions.
fn prove_and_verify(
    program: &Program,
    public: [F128; 2],
    n_blake3: usize,
) -> (lean_vm_core::cpu::Proof, verifier::Summary) {
    let t = std::time::Instant::now();
    let (proof, stats) = prove(program, &[], public, 1).expect("honest run proves");
    let prove_ms = t.elapsed().as_secs_f64() * 1e3;
    assert_eq!(stats.table_heights[verifier::layout::OP_BLAKE3], n_blake3);
    let t = std::time::Instant::now();
    let summary = verify(program, &public, &proof).expect("honest proof verifies");
    eprintln!(
        "BLAKE3 rows {n_blake3}: cycles {}, prove {prove_ms:.1} ms, verify {:.1} ms, stream {} scalars, flock scalars {:?}, table rows {:?}",
        stats.cycles,
        t.elapsed().as_secs_f64() * 1e3,
        proof.stream.len(),
        summary.flock_scalars,
        stats.table_heights
    );
    (proof, summary)
}

#[test]
fn one_block_hash_is_blake3() {
    let seq: Vec<u8> = (0u8..64).collect();
    let m = words(&seq);
    let iv = digest_cells(&IV);
    let flags = CHUNK_START | CHUNK_END | ROOT;
    let h = compress(&IV, &m, 0, 64, flags);
    // blake3(0..64), the `blake3` crate's digest.
    assert_eq!(
        h,
        [
            0x4171ed4e, 0xd45c4aea, 0x6b6088b7, 0xe2463fd2, 0xac9caf12, 0x7ddcaceb, 0xc76d4c1f, 0x981b51f2
        ]
    );
    let p = program(
        ONE,
        &[
            ("A0", cell(&m[0..4])),
            ("A1", cell(&m[4..8])),
            ("B0", cell(&m[8..12])),
            ("B1", cell(&m[12..16])),
            ("CV0", iv[0]),
            ("CV1", iv[1]),
            ("MD", md(0, 64, flags)),
        ],
    );
    let public = digest_cells(&h);
    let (proof, summary) = prove_and_verify(&p, public, 1);
    assert!(!summary.flock_scalars.is_empty());

    // A digest one bit off is no run at all: the program's write of it conflicts with the instruction's.
    let mut wrong = public;
    wrong[0].c0 ^= 1;
    match prove(&p, &[], wrong, 1) {
        Err(ProveError::Execution(ExecError { .. })) => {}
        other => panic!("a wrong digest must not prove: {:?}", other.map(|_| ())),
    }
    // And the honest proof is no proof of the wrong digest.
    assert!(verify(&p, &wrong, &proof).is_err());
}

#[test]
fn two_block_chunk_chains_as_blake3() {
    let seq: Vec<u8> = (0u8..128).collect();
    let (m1, m2) = (words(&seq[..64]), words(&seq[64..]));
    let iv = digest_cells(&IV);
    let mid = compress(&IV, &m1, 0, 64, CHUNK_START);
    let h = compress(&mid, &m2, 0, 64, CHUNK_END | ROOT);
    // blake3(0..128), the `blake3` crate's digest.
    assert_eq!(
        h,
        [
            0x05577ef1, 0x7865b264, 0xf4b73bc3, 0x39f54346, 0xdf054b62, 0x1fc8761a, 0x48d5ac30, 0xef454bc4
        ]
    );
    let p = program(
        TWO,
        &[
            ("A0", cell(&m1[0..4])),
            ("A1", cell(&m1[4..8])),
            ("B0", cell(&m1[8..12])),
            ("B1", cell(&m1[12..16])),
            ("C0", cell(&m2[0..4])),
            ("C1", cell(&m2[4..8])),
            ("D0", cell(&m2[8..12])),
            ("D1", cell(&m2[12..16])),
            ("CV0", iv[0]),
            ("CV1", iv[1]),
            ("MD1", md(0, 64, CHUNK_START)),
            ("MD2", md(0, 64, CHUNK_END | ROOT)),
        ],
    );
    prove_and_verify(&p, digest_cells(&h), 2);
}

/// `n` chained one-block hashes, padded to a power of two of Flock instances; every tampered stream position tried is
/// refused, in Flock's part of the proof and around it.
fn chain(n: usize, tamper: bool) {
    let flags = CHUNK_START | CHUNK_END | ROOT;
    let x0: [u32; 8] = std::array::from_fn(|i| 0x0101_0101u32.wrapping_mul(i as u32 + 1));
    let mut x = x0;
    for _ in 0..n {
        let mut block = [0u32; 16];
        block[..8].copy_from_slice(&x);
        block[8..].copy_from_slice(&x);
        x = compress(&IV, &block, 0, 64, flags);
    }
    let iv = digest_cells(&IV);
    let start = digest_cells(&x0);
    let replacements: BTreeMap<String, String> = [
        ("N_PLACEHOLDER", n.to_string()),
        ("CV0", lit(iv[0])),
        ("CV1", lit(iv[1])),
        ("MD", lit(md(0, 64, flags))),
        ("X0", lit(start[0])),
        ("X1", lit(start[1])),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let ast = parse_with_replacements(CHAIN, &replacements).expect("parse zkDSL program");
    let p = Program::from(compile(&ast));
    let public = digest_cells(&x);
    let (proof, summary) = prove_and_verify(&p, public, n);
    if tamper {
        let flock = summary.flock_scalars.clone();
        let positions = [
            flock.start,
            flock.start + 70,
            (flock.start + flock.end) / 2,
            flock.end - 1,
            flock.start - 1,
            flock.end,
        ];
        for at in positions {
            let mut bad = proof.clone();
            bad.stream[at] = verifier::E::new(bad.stream[at].c0 ^ 1, bad.stream[at].c1);
            assert!(
                verify(&p, &public, &bad).is_err(),
                "stream position {at} tampered ({flock:?})"
            );
        }
    }
}

#[test]
fn chain_of_seven() {
    chain(7, false);
}

#[test]
fn chain_of_300_and_tampering() {
    chain(300, true);
}

/// Measurement, not a check: `BLAKE3_N` chained compressions (default 2020), proved 3 times; the median prove, one
/// verify, the proof's bytes and the process's peak resident memory.
#[test]
#[ignore]
fn bench_chain() {
    let n: usize = std::env::var("BLAKE3_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2020);
    let flags = CHUNK_START | CHUNK_END | ROOT;
    let x0: [u32; 8] = std::array::from_fn(|i| 0x0101_0101u32.wrapping_mul(i as u32 + 1));
    let mut x = x0;
    for _ in 0..n {
        let mut block = [0u32; 16];
        block[..8].copy_from_slice(&x);
        block[8..].copy_from_slice(&x);
        x = compress(&IV, &block, 0, 64, flags);
    }
    let iv = digest_cells(&IV);
    let start = digest_cells(&x0);
    let replacements: BTreeMap<String, String> = [
        ("N_PLACEHOLDER", n.to_string()),
        ("CV0", lit(iv[0])),
        ("CV1", lit(iv[1])),
        ("MD", lit(md(0, 64, flags))),
        ("X0", lit(start[0])),
        ("X1", lit(start[1])),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let p = Program::from(compile(&parse_with_replacements(CHAIN, &replacements).unwrap()));
    let public = digest_cells(&x);
    let mut times = Vec::new();
    let mut last = None;
    for _ in 0..3 {
        let t = std::time::Instant::now();
        let (proof, stats) = prove(&p, &[], public, 1).expect("proves");
        times.push(t.elapsed().as_secs_f64() * 1e3);
        last = Some((proof, stats));
    }
    times.sort_by(f64::total_cmp);
    let (proof, stats) = last.unwrap();
    let t = std::time::Instant::now();
    verify(&p, &public, &proof).expect("verifies");
    let verify_ms = t.elapsed().as_secs_f64() * 1e3;
    let hwm = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l.to_string()))
        .unwrap_or_default();
    eprintln!(
        "BENCH n={n} cycles={} prove_median_ms={:.1} verify_ms={verify_ms:.2} proof_kib={:.1} {hwm}",
        stats.cycles,
        times[1],
        proof.to_bytes().len() as f64 / 1024.0
    );
}

/// The verifier fixes the zerocheck's seven constant coordinates itself; the prover's are the same seven, so the
/// verifier's independence test (`verifier::flock`'s) is about the point every proof is checked at.
#[test]
fn fixed_zerocheck_coordinates_agree() {
    use flock::zerocheck::univariate_skip_optimized::{medium_challenges, small_challenges};
    let prover: Vec<(u64, u64)> = small_challenges()
        .iter()
        .chain(medium_challenges().iter())
        .map(|c| (c.c0, c.c1))
        .collect();
    let verifier: Vec<(u64, u64)> = verifier::flock::fixed_challenges()
        .iter()
        .map(|c| (c.c0, c.c1))
        .collect();
    assert_eq!(prover, verifier);
}
