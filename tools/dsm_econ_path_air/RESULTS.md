# Results — 2026-10-21, first runs

Plonky3 at `a4982ec0` (git, 2026-10-21). KoalaBear, degree-4 extension, FRI
with `log_blowup` 1, 100 queries, 16 PoW bits (the Plonky3 benchmark defaults;
roughly 100 bits conjectured — not yet tuned to a stated target).

## Apple M-series, 18 cores, rustup 1.98.0 (`run_bench.sh`)

| paths | rows | trace | prove | verify | peak RSS | proof |
|---|---|---|---|---|---|---|
| 1 (one leaf) | 512 | 19.8 MB | **39 ms** | 21 ms | 103 MB | 4.24 MB |
| 2 (one mutation: pre + post) | 1024 | 39.6 MB | **63 ms** | 22 ms | 165 MB | 4.26 MB |
| 4 (a transfer touching two leaves) | 2048 | 79.3 MB | **100 ms** | 22 ms | 284 MB | 4.28 MB |

## Linux x86-64 container, 2 cores, 7 GB

| paths | prove | verify | peak RSS |
|---|---|---|---|
| 1 | 637 ms | 84 ms | 58 MB |

The two-core box is the pessimistic proxy for a phone until one is attached:
a mid-range Android SoC has four performance cores and NEON, which Plonky3's
31-bit field arithmetic uses. Read the phone estimate for a two-leaf transfer
as **one to three seconds, under 300 MB**, comfortably inside the FibRace
envelope (3–10 s, ≥ 3 GB RAM) that 1,420 phone models already proved at.

## Reading the numbers

- **Prover time scales linearly in rows** and is dominated by the FFT and
  Merkle commitment of a 9,680-column trace; `Blake3Air` is wide by design
  (all state as bits) and that width, not the number of rows, is where the
  cost sits. A narrower BLAKE3 arithmetization would cut both time and proof
  size but is not needed to decide viability.
- **Proof size (~4.2 MB) is almost all query openings** of that wide trace
  (100 queries × opened rows). It barely moves with path count. It matters only
  if the base proof itself were stored; in the recursive design only the outer
  proof is, and the inner proof is consumed in-circuit. Fewer queries with more
  PoW or higher blowup trades prover time for size when that matters.
- **Verification is constant** (~22 ms) whatever the path count — the property
  the acceptance rule needs.
- **Memory is the binding constraint on phones**, as FibRace found; 284 MB for
  a transfer is an order of magnitude inside the headroom.

## What this decides

Proving a full economic root advance on the sender's device is viable with
headroom: the path cost that dominates `advance_validated` is tens of
milliseconds on a laptop and single-digit seconds in the worst reading on a
phone. The remaining cost to measure is the recursion layer
(`Plonky3-recursion` reports ~100 ms per layer on an M4 Pro with Poseidon2
hashing of the inner proof), which is independent of lineage length.
