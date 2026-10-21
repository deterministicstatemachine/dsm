// SPDX-License-Identifier: MIT OR Apache-2.0

//! Prove `N` economic SMT paths and report what it cost.
//!
//! ```text
//! dsm_econ_path_air [--paths N] [--log-blowup B] [--queries Q] [--pow P]
//! ```
//!
//! `N` is a power of two (default 1: one leaf's path; 2 is one mutation, pre
//! and post; 4 is a transfer touching two leaves). Prints trace shape,
//! generation / proving / verification time, proof size and peak RSS.

use std::time::Instant;

use dsm_econ_path_air::{EconSmtPathAir, PathWitness, SMT_HEIGHT, public_values};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use p3_util::log2_strict_usize;
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

type F = KoalaBear;
type EF = BinomialExtensionField<F, 4>;
type Perm16 = Poseidon2KoalaBear<16>;
type Perm24 = Poseidon2KoalaBear<24>;
type Sponge = PaddingFreeSponge<Perm24, 24, 16, 8>;
type Compress = TruncatedPermutation<Perm16, 2, 8, 16>;
type ValMmcs = MerkleTreeMmcs<<F as p3_field::Field>::Packing, <F as p3_field::Field>::Packing, Sponge, Compress, 2, 8>;
type ChallengeMmcs = ExtensionMmcs<F, EF, ValMmcs>;
type Challenger = DuplexChallenger<F, Perm24, 24, 16>;
type Dft = Radix2DitParallel<F>;
type Pcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
type Config = StarkConfig<Pcs, EF, Challenger>;

struct Args {
    paths: usize,
    log_blowup: usize,
    queries: usize,
    pow_bits: usize,
}

fn parse_args() -> Args {
    let mut args = Args { paths: 1, log_blowup: 1, queries: 100, pow_bits: 16 };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        let n: usize = value.parse().unwrap_or_else(|_| panic!("{flag}: not a number: {value}"));
        match flag.as_str() {
            "--paths" => args.paths = n,
            "--log-blowup" => args.log_blowup = n,
            "--queries" => args.queries = n,
            "--pow" => args.pow_bits = n,
            other => panic!("unknown flag {other}"),
        }
    }
    assert!(args.paths.is_power_of_two(), "--paths must be a power of two");
    args
}

fn peak_rss_bytes() -> u64 {
    // SAFETY: getrusage writes into the zeroed struct we hand it.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    assert_eq!(rc, 0, "getrusage failed");
    let maxrss = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") { maxrss } else { maxrss * 1024 }
}

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

fn main() {
    let args = parse_args();

    // Random witnesses: the cost does not depend on their values.
    let mut rng = SmallRng::seed_from_u64(0x5a5a);
    let paths: Vec<PathWitness> = (0..args.paths).map(|_| random_path(&mut rng)).collect();
    let air = EconSmtPathAir::new(paths.iter().map(|p| p.key).collect());
    let pvs = public_values::<F>(&paths);

    // Poseidon2 for the proof system's own Merkle trees and the challenger.
    // Fixed seed: a deployment pins the round constants; the choice does not
    // affect cost.
    let mut perm_rng = SmallRng::seed_from_u64(1);
    let perm16 = Perm16::new_from_rng_128(&mut perm_rng);
    let perm24 = Perm24::new_from_rng_128(&mut perm_rng);
    let val_mmcs = ValMmcs::new(Sponge::new(perm24.clone()), Compress::new(perm16), 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri_params = FriParameters {
        log_blowup: args.log_blowup,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: args.queries,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: args.pow_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri_params);
    let config = Config::new(pcs, Challenger::new(perm24));

    let t = Instant::now();
    let trace = air.generate_trace::<F>(&paths, args.log_blowup);
    let gen_time = t.elapsed();
    let rows = trace.height();
    let width = trace.width();
    let log_rows = log2_strict_usize(rows);

    let t = Instant::now();
    let (pp_prover, pp_vk) = setup_preprocessed(&config, &air, log_rows)
        .expect("preprocessed setup")
        .expect("this AIR has preprocessed columns");
    let setup_time = t.elapsed();

    let t = Instant::now();
    let proof = prove_with_preprocessed(&config, &air, trace, &pvs, Some(&pp_prover)).expect("prove");
    let prove_time = t.elapsed();
    let proof_bytes = postcard::to_allocvec(&proof).expect("serialize proof").len();

    let t = Instant::now();
    verify_with_preprocessed(&config, &air, &proof, &pvs, Some(&pp_vk)).expect("verify");
    let verify_time = t.elapsed();

    println!("paths              {}", args.paths);
    println!("trace              {rows} rows x {width} cols ({:.1} MB of field elements)", (rows * width * 4) as f64 / 1e6);
    println!("fri                log_blowup={} queries={} query_pow_bits={}", args.log_blowup, args.queries, args.pow_bits);
    println!("trace generation   {gen_time:?}");
    println!("preprocessed setup {setup_time:?}");
    println!("prove              {prove_time:?}");
    println!("verify             {verify_time:?}");
    println!("proof size         {proof_bytes} bytes");
    println!("peak rss           {:.0} MB", peak_rss_bytes() as f64 / 1e6);
}
