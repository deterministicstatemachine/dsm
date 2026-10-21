# Results — 2026-10-21

Plonky3 at `a4982ec0` (git, 2026-10-21). KoalaBear, degree-4 extension, FRI
with `log_blowup` 1, 100 queries, 16 PoW bits (the Plonky3 benchmark defaults;
roughly 100 bits conjectured — not yet tuned to a stated target).

## Apple M-series, 18 cores, cargo 1.98.0, `run_bench.sh` (this AIR: leaf hash included)

| paths | path rows | trace rows | trace | prove | verify | peak RSS | proof |
|---|---|---|---|---|---|---|---|
| 1 (one leaf) | 514 | 1024 | 39.6 MB | **56 ms** | 23 ms | 161 MB | 4.26 MB |
| 2 (one mutation: pre + post) | 1028 | 2048 | 79.3 MB | **95 ms** | 24 ms | 291 MB | 4.28 MB |
| 4 (a transfer touching two leaves) | 2056 | 4096 | 158.6 MB | **165 ms** | 24 ms | 522 MB | 4.31 MB |

One run each, measured once; no repetition or variance.

## The earlier AIR (no leaf hash; 512 rows per path, no padding), same machine

| paths | prove | verify | peak RSS | proof |
|---|---|---|---|---|
| 1 | 39 ms | 21 ms | 103 MB | 4.24 MB |
| 2 | 63 ms | 22 ms | 165 MB | 4.26 MB |
| 4 | 100 ms | 22 ms | 284 MB | 4.28 MB |

Linux x86-64 container, 2 cores, 7 GB, that AIR, one path: 637 ms prove, 84 ms
verify, 58 MB. **Not re-measured on this AIR.**

## Reading the numbers

- **The leaf hash costs more than its two rows.** 514 rows per path is just past
  a power of two, so the trace doubles: 56 ms against 39 ms for one path, and
  peak memory 161 MB against 103 MB. The padding is not free; the 510 spare rows
  of a one-path trace are where the leaf-state hash and the next hashes of a
  step should go before any further doubling is accepted.
- **Prover time scales with trace height** and is dominated by the FFT and
  Merkle commitment of a 9,680-column trace; `Blake3Air` is wide by design (all
  state as bits). A narrower BLAKE3 arithmetization would cut time and proof
  size; not tried.
- **Proof size (~4.3 MB) is almost all query openings** of that wide trace. It
  barely moves with path count. In a recursive design only the outer proof is
  stored; not built.
- **Verification is nearly constant** (23–24 ms) whatever the path count.
- **Memory** grows with trace height: 522 MB for a four-path proof. This is the
  number that decides whether a phone can run it; no phone was measured.

## What this does and does not decide

Measured: a Mac proves and verifies the Merkle-path statement for up to four
leaves in under 200 ms and 522 MB. Not measured, and not decided by this:
a phone's time or memory (the earlier two-core container figure, roughly 16x the
Mac for one path, is the only proxy, and it is for the older AIR); the recursion
layer; the cost of the rest of the step predicate; the authority and finality
facts a valid step also needs.
