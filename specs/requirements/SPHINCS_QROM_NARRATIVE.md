# DSM BLAKE3 SPHINCS+ against quantum adversaries: a narrative mapping

Status: **NOT MACHINE-CHECKED.** Phase 2 of audit-prep, 2026-10-07. This is a
written argument that maps each term of DSM's classical reduction onto
published quantum-random-oracle (QROM) bounds. No Lean statement backs it:
Lean core has no model of quantum states or superposition queries, and none
is claimed. The cited bounds are for the standard SPHINCS+ tweakable-hash
constructions; that DSM's BLAKE3 instantiation meets the same assumptions is
not established.

## The setting

The adversary makes classical signing queries and `q` quantum (superposition)
queries to each random oracle. Search problems that cost `q` classical
queries per success probability `p` cost about `q^2` quantum queries
(Grover), so bounds of the form `q · p` become roughly `q^2 · p`.

Sources:
* A. Hülsing, M. Kudinov, "Recovering the tight security proof of SPHINCS+",
  ASIACRYPT 2022, ePrint 2022/346. Section 8, Table 1 gives QROM success
  probabilities for the properties the tight proof uses: SM-TCR
  Θ((q+1)²/2^n) (proven), SM-DSPR Θ((q+1)²/2^n) (conjectured), SM-PRE
  Θ((q+1)²/2^n) (based on a conjecture), PRF and SM-UD Θ(q/√2^n) (proven), and
  ITSR Θ((q+1)²·X) (conjectured), X the classical per-query covering
  probability.
* A. Hülsing, J. Rijneveld, F. Song, "Mitigating multi-target attacks in
  hash-based signatures", PKC 2016, ePrint 2015/1256: average-case search
  with a λ-fraction of marked inputs succeeds with probability at most
  8λ(q+1)² (restated as Theorem 4 in Hülsing–Kudinov).
* M. Barbosa et al., "A tight security proof for SPHINCS+, formally
  verified", ePrint 2024/910 (EasyCrypt, classical).

## Term by term

| DSM reduction term | Classical ROM bound (checked) | Quantum counterpart (cited, not checked) |
|---|---|---|
| seed / KDF / PRF / PRF_msg hops (key finding) | `q / 2^256`, `q / 2^(8n)` | PRF distinguishing Θ(q/√2^κ) for a κ-bit secret (Grover): `q/2^128` for 256-bit keys, `q/2^(4n)` for the n-byte `SK.seed` and `SK.prf` |
| tweak collision | `(q + V)/2^(8n)` | SM-TCR: Θ((q+1)²/2^(8n)), proven |
| hidden WOTS chain value / FORS secret | `(q + V)/2^(8n)` | preimage-type search: 8(q+1)²/2^(8n) per target (HRS16), SM-PRE-type |
| ITSR | `(q + 1) · 2^-128` (SPX128f), `(q + 1) · 2^-255` (SPX256f) | Θ((q+1)² · X), conjectured, with X the checked per-query bound |

## What it suggests

Summing the quantum counterparts with the classical per-query values gives,
roughly:

* **SPX128f:** success becomes constant at about `q ≈ 2^61–2^64` quantum
  queries (the `(q+1)²·2^-128` terms dominate, and the PRF hops on 128-bit
  secrets give the same order). That is the same order as Grover search on a
  128-bit key, the yardstick of NIST category 1.
* **SPX256f:** about `q ≈ 2^124–2^128` quantum queries, the order of the
  category 5 yardstick.

These estimates do not establish a NIST category for DSM's instantiation.

These are order-of-magnitude readings with the constants from the cited
papers, not theorems about DSM.

## What would be needed to make it a theorem

1. A formal quantum query model (states, unitary oracles, measurement), not
   available in Lean core; EasyCrypt/QRHL or a Mathlib-based development
   would be the realistic route.
2. The one-way-to-hiding lemma (Unruh; Ambainis, Hamburg, Unruh) for the
   hybrid hops, replacing the classical identical-until-bad step.
3. QROM bounds for tweak collision and preimage search on DSM's thash with
   its full 32-byte address and public-seed-derived key, and the ITSR bound
   for DSM's derive-mode XOF (the latter is only conjectured even for the
   standard constructions).
4. The classical gaps listed in `SPHINCS_ROM_BOUND.md` ("What is argued"),
   which a quantum proof would also need.
