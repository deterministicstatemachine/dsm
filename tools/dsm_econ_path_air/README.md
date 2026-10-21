# `dsm_econ_path_air` — the economic SMT path as a STARK, and what it costs

A prover-cost spike for the validity proof `π_n ⊢ Valid(ρ_0 → ρ_n)` named in
DSM Amendment A8 and A15 phase C. It proves the one part of `advance_validated`
whose cost is not trivial: the authentication path of a leaf in `R_econ`, a
256-level sparse Merkle tree under BLAKE3 (`dsm::economic::tree`,
`root_from_path`). Everything else a step verifies — conservation arithmetic,
write-set closure, the credit/source bijection — is a few hundred constraints
beside it.

This crate is its own workspace, not a member of the DSM workspace, and nothing
in `dsm` depends on it.

## What is proven

For `N` paths (a power of two), each with its own key:

- every row is one BLAKE3 compression, constrained by Plonky3's `Blake3Air` as
  a sub-AIR over the first `NUM_BLAKE3_COLS` columns;
- two rows are one `econ_node(l, r) = BLAKE3(tag ‖ 0x00 ‖ l ‖ r)`: the message
  is 89 bytes, so block 0 (64 bytes, IV, `CHUNK_START`) and block 1 (25 bytes,
  chained, `CHUNK_END | ROOT`), with the tag bytes, lengths, counter and flags
  fixed by constraints;
- the two 32-byte operands of each level are `(current, sibling)` or
  `(sibling, current)` as the key bit at that level selects — the key bits are
  a **preprocessed** column the verifier derives from the key, so the prover
  cannot choose the position the leaf sits at;
- each level's node is the next level's `current`;
- the first `current` of each path equals the leaf public values and the last
  node equals the root public values, as sixteen u16 limbs each.

The host-side hash the AIR is held to is the `blake3` crate applied exactly as
`dsm_domain_hasher` applies it; `the_two_compressions_are_econ_node` checks the
AIR's two-compression schedule against it, and the constraint test checks that
a wrong leaf or a changed sibling bit fails.

## What is not in this spike

- `econ_leaf(key, value)` (one more node-shaped hash per leaf).
- The step predicate itself (`advance_validated`): conservation, write set,
  credit sources. Cheap, but not written.
- Recursion. `Plonky3-recursion` verifies a `p3-uni-stark` proof in-circuit;
  this AIR is a plain uni-stark, so it is the right shape to feed it.
- The finality facts of ancestral credit sources (A15 phase C's `F_n`,
  Storage §24 item 15). Not a proving problem; an accumulator problem.
- A fixed Poseidon2 round-constant set. The bench seeds the permutation; a
  deployment pins constants. Cost is unaffected.

## Shape

| | |
|---|---|
| rows per path | 512 (2 compressions × 256 levels) |
| width | 9680 columns (9168 `Blake3Air` + 256 `current` bits + 256 `sibling` bits) |
| preprocessed | 4 + N columns (`is_a`, key bit, path start, path end, one selector per path) |
| public values | 32 per path (leaf and root as u16 limbs) |
| max constraint degree | 3 |
| field | KoalaBear, degree-4 extension for challenges |
| PCS | FRI (`log_blowup` 1, 100 queries, 16 PoW bits by default) |

## Results

`./run_bench.sh` builds with the repository's pinned toolchain and proves 1, 2
and 4 paths (one leaf; one mutation, pre and post; a transfer touching two
leaves). Numbers below are from this spike's first runs; the Mac is the
reference until a phone is attached.

See `RESULTS.md` beside this file.

## Running

```sh
cargo test --release          # the AIR against the blake3 crate; constraints hold / fail
cargo run --release -- --paths 2 [--log-blowup 1] [--queries 100] [--pow 16]
./run_bench.sh [logfile]
```

Plonky3 is taken from git at a pinned commit (see `Cargo.toml`): the published
`p3-blake3-air` 0.8.0 fills counter, length and flags from the batch rather
than from each compression, which is not BLAKE3; the explicit-metadata
generator landed after the release.
