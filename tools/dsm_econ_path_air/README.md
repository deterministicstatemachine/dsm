# `dsm_econ_path_air` — the economic SMT path as a STARK, and what it costs

A prover-cost spike for the validity proof `π_n ⊢ Valid(ρ_0 → ρ_n)` named in
DSM Amendment A8 and A15 phase C. It proves the one part of `advance_validated`
whose cost is not trivial: the authentication path of a leaf in `R_econ`, a
256-level sparse Merkle tree under BLAKE3 (`dsm::economic::tree`,
`root_from_path`), starting from `econ_leaf(key, value)`.

This crate is its own workspace, not a member of the DSM workspace, and nothing
in `dsm` depends on it.

## What is proven

For `N` paths, each with its own key, the statement per path is
`root = fold(econ_leaf(key, value), siblings)`, with `key`, `value` and `root`
public (sixteen u16 limbs each) and the siblings private:

- every row is one BLAKE3 compression, constrained by Plonky3's `Blake3Air` as
  a sub-AIR over the first `NUM_BLAKE3_COLS` columns;
- two rows are one hash `BLAKE3(tag ‖ 0x00 ‖ a ‖ b)`: the message is 89 bytes,
  so block 0 (64 bytes, IV, `CHUNK_START`) and block 1 (25 bytes, chained,
  `CHUNK_END | ROOT`), with the tag bytes, separator, padding, block lengths,
  counters and flags fixed by constraints;
- a path is one leaf hash (`DSM/economic-smt-leaf/v1`, operands `key ‖ value`)
  and 256 node hashes (`DSM/economic-smt-node/v1`), 514 rows;
- the two 32-byte operands of each node hash are `(current, sibling)` or
  `(sibling, current)` as the key bit at that level selects — the key bits are
  a **preprocessed** column the verifier derives from the key, so the prover
  cannot choose the position the leaf sits at;
- each hash's output is the next hash's `current`, from the leaf hash into level
  0 and from each level into the next;
- the leaf hash's `key` and `value` operands equal the public key and value, and
  the last output equals the public root.

The host-side hash the AIR is held to is the `blake3` crate applied exactly as
`dsm_domain_hasher` applies it: `the_two_compressions_are_econ_node` and
`…_econ_leaf` check the AIR's two-compression schedule against it.

## What is not proven here

- A leaf that is **absent** on one side of a mutation (an insertion or a
  removal): its leaf node is the zero digest, not a hash, so the leaf hash
  cannot be the first step.
- The step predicate (`advance_validated`): the leaf-state hash
  `H(economic-leaf-state ‖ CCB(state))`, conservation and borrow arithmetic,
  write-set closure, the credit/source bijection.
- Authority: the SPHINCS+ signature (P0–P6) over the transition, register
  finality, and the finality facts of ancestral credit sources (A15 phase C's
  `F_n`, Storage §24 item 15). This AIR proves a Merkle-path statement, not that
  a transition is valid or that anyone was entitled to make it.
- Recursion. `Plonky3-recursion` verifies a `p3-uni-stark` proof in-circuit;
  this AIR is a plain uni-stark, so it is the right shape to feed it. Not built
  or measured.
- A phone. Every number below is from a Mac.
- A fixed Poseidon2 round-constant set. The bench seeds the permutation; a
  deployment pins constants. Cost is unaffected.

## Shape

| | |
|---|---|
| rows per path | 514 (leaf hash 2 + 256 levels × 2), the trace padded to a power of two |
| width | 9680 columns (9168 `Blake3Air` + 256 `current` bits + 256 `sibling` bits) |
| preprocessed | 7 + N columns (`is_a`, `is_b`, leaf rows, leaf row A, key bit, carry, path end, one selector per path) |
| public values | 48 per path (key, value, root as u16 limbs) |
| max constraint degree | 3 |
| field | KoalaBear, degree-4 extension for challenges |
| PCS | FRI (`log_blowup` 1, 100 queries, 16 PoW bits by default) |

514 is two rows past a power of two, so one path pads to 1024 rows, two to 2048
and four to 4096: **the leaf hash doubles the trace.** The spare rows (510 of 1024
for one path) are the room for the leaf-state hash and the next step's hashes.

## Tests and mutation controls

`cargo test --release` runs 28 tests: the schedule against the `blake3` crate
(leaf and node), the padding, honest traces of one, two and four paths, and 22
`#[should_panic]` tests, each building a trace that is honest everywhere except
one link and checking that `p3_air::check_constraints` rejects it:
wrong key, value or root public value; a sibling changed after hashing (in either
block); a value changed in the leaf row; the leaf hash not carried into level 0;
a spliced path; a trace built for another key; a second compression not chained
to the first; a first compression not started from the IV; other flags, other
lengths and a block counter on either compression; another domain tag; a nonzero
separator byte; a right operand changed in either block; a nonzero padding word.

Mutation controls, executed 2026-10-21 (one build with every constraint
switched by `DSM_MUTANT`, then 22 mutants and an unmutated control run in
parallel against the one binary): the control was green, and **all 22 mutants
went red** — each by a named test in the list above. They remove, one at a time,
the key, value and root boundaries; the carry; the block 0 and block 1 operand
bindings (and, separately, the tag, separator, left operand, right head, right
tail and tail padding); the leaf tag; the direction selection; the chaining of
the second compression; the IV; the counter, length and flags of each
compression.

Two limits. The tests and mutants check the **constraints** with
`check_constraints`, not the prover: the proofs that `run_bench.sh` makes verify
(`verify_with_preprocessed` is expected to succeed), but no test tampers with a
proof. And one constraint was removed rather than tested: the boolean checks on
`current` and `sibling`, which every bit is already equated to a message bit
that `Blake3Air` constrains boolean, so removing them changes nothing the
tests could see.

## Results

`sh run_bench.sh [log]` builds with the repository's pinned toolchain, runs the
tests, and proves 1, 2 and 4 paths (one leaf; one mutation, pre and post; a
transfer touching two leaves). See `RESULTS.md` beside this file.

## Running

```sh
cargo test --release          # the AIR against the blake3 crate; constraints hold / fail
cargo run --release -- --paths 2 [--log-blowup 1] [--queries 100] [--pow 16]
sh run_bench.sh [logfile]
```

Plonky3 is taken from git at a pinned commit (see `Cargo.toml`): the published
`p3-blake3-air` 0.8.0 fills counter, length and flags from the batch rather
than from each compression, which is not BLAKE3; the explicit-metadata
generator landed after the release.
