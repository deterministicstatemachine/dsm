# DSM BLAKE3 SPHINCS+: classical security level in the random-oracle model

Status: phase 2 of audit-prep, 2026-10-07, after the frozen tag
`audit-freeze-2026-10-07` (which this does not change). Lean 4 core only, no
`sorry`, no `axiom`, no `native_decide`; every theorem named here is in
`LEAN_AXIOM_LEDGER.tsv` on core axioms.

**What this is.** A numerical bound on forging DSM's SPHINCS+ (SPX128f,
SPX256f) under an explicit idealized model. **What it is not.** A statement
about BLAKE3 or ChaCha20: in the model they are replaced by ideal random
functions. If a BLAKE3 role does not behave like an independent random
function, these numbers say nothing about it.

## The model (explicit, kernel-checked definitions)

| Element | Definition | File |
|---|---|---|
| Random oracle | one lazily sampled oracle answers **every** primitive request: keyed BLAKE3 (each key), each `derive_key` context, the h_msg XOF, and ChaCha20 seed expansion. The i-th fresh request gets tape entry i truncated to its output length; a repeat gets its first answer. Distinct requests are therefore independent uniform values: each role is an independent random oracle. | `RomOracle.lean` (`run`) |
| Randomness | a tape of uniform entries; probabilities are exact counts over all tapes (`tsum`), no floating point | `RomTape.lean` |
| Adversary | a query tree `QT`: every oracle access is an explicit `ask`, tagged adversary-side; `Within T q` caps the queries on every path at `q_h` | `RomOracle.lean` |
| Challenger | the model's own key generation, signing and verification, which are monad-generic and so run unchanged as query trees, tagged challenger-side | `Model.lean` |
| Signing queries | `q_s ≤ 2^64`, adaptive | — |
| Forgery check | verification of the forged pair, tagged adversary-side (its `V = verifyCost` draws count against the adversary) | `QueryCost.lean` |

## Role bounds (kernel-checked)

| Role game | Bound | Theorem |
|---|---|---|
| A fresh draw hits, mod M, a value fixed before it was drawn | `1/M` per target | `fresh_hits` |
| Any of an adaptive run's designated pairs of fresh draws agree mod M | `B/M`, B = pairs on every tape | `partner_hits`, `rom_partner_bound` |
| **Tweak collision** (thash role): an adversary-side keyed request collides in its n-byte answer with the challenger's request under the same key and 32-byte address but a different input | `q_adv / 2^(8n)` given challenger tweak single use | `rom_tweak_collision`, `pairs_le_adv` |
| **Secret guessing** (PRF, KDF, PRF_msg keys, master seed, hidden values): a secret uniform in `[0, K)` independent of the run is among `q_adv` guesses | `q_adv / K` | `rom_secret_guess`, `guess_bound` |
| **ITSR** (h_msg role): a fresh uniform digest is covered at its leaf by `q_s` uniform signature leaves (their FORS indices arbitrary) | exact sum over `g ≤ G` of `(g^k − (g−1)^k) q^g / (g! L^g t^k)` plus `q^(G+1)/((G+1)! L^(G+1))` | `itsr_static`, `many_on_leaf`, `covered_count` |
| ITSR, SPX128f, `q_s ≤ 2^64` | `≤ 2^-128` per fresh digest | `itsr_spx128f` (`itsr_check_128f` by `decide`) |
| ITSR, SPX256f, `q_s ≤ 2^64` | `≤ 2^-255` per fresh digest | `itsr_spx256f` (`itsr_check_256f`) |

Controls: `RomChecks.lean` runs a small tree against two tapes: repeated
requests are answered from their first draw, equal answers on a same-tweak
pair are counted (the event is reachable), different answers are not, and the
partner accounting is exact.

## Composition and the numbers

The classical reduction (`euf_cma_reduction`, unchanged) bounds a forgery by
five hybrid hops plus four extracted events. In the random-oracle experiment
each becomes one role game:

| Reduction term | ROM term | Role bound |
|---|---|---|
| seed PRG hop | adversary queries ChaCha at the master seed | `q_h / 2^256` |
| PRF-key KDF hop | adversary queries `derive_key(prf, SK.seed)` | `q_h / 2^(8n)` |
| PRF function hop | adversary queries under the PRF key | `q_h / 2^256` |
| message-key KDF hop | adversary queries `derive_key(prf-msg, SK.prf)` | `q_h / 2^(8n)` |
| message function hop | adversary queries under the PRF_msg key | `q_h / 2^256` |
| canonical collision (`CanonCollIn`) | tweak collision | `(q_h + V) / 2^(8n)` |
| WOTS preimage (`WotsEvent`) | guessing an unrevealed chain value at its address | `(q_h + V) / 2^(8n)` |
| unrevealed FORS secret | guessing an unrevealed FORS secret at its address | `(q_h + V) / 2^(8n)` |
| ITSR covered | a covered fresh digest among `q_h + 1` candidates | `(q_h + 1) · ITSR` |

Summed and checked (`RomBound.lean`):

* **SPX128f** (n = 16, V = 11,872): ε ≤ (6 q_h + 3V + 1)/2^128 + 3 q_h/2^256,
  hence **ε ≤ q_h · 2^-125 for q_h ≥ 2^16** (`rom_level_128f`).
* **SPX256f** (n = 32, V = 17,523): ε ≤ (10 q_h + 3V + 2)/2^256,
  hence **ε ≤ q_h · 2^-252 for q_h ≥ 2^14** (`rom_level_256f`).

How to read these numbers. They are query-dependent upper bounds, and they are
conditional twice: on the random-oracle model, and on the five argued steps
below. Together they say that an adversary in that model would need on the
order of 2^125 (SPX128f) or 2^252 (SPX256f) oracle queries for constant success
probability, with up to 2^64 signatures per key. **They are not a proved
security level for DSM's SPHINCS+**: the inequalities are machine-checked, but
the claim that they bound the real scheme's forging probability is not.

Where the residual risk sits. The step "a forgery yields one of the four
events" is machine-checked (`final_forge_events`, for every oracle). What is
not machine-checked is the probability of those events in the random-oracle
run: the five links below. The two that matter most are the hidden-value
independence behind the WOTS and FORS events (link 3) and ITSR under adaptive
signing (link 4). This is the kind of step where published SPHINCS+ tightness
arguments have gone wrong before: Hülsing and Kudinov (ePrint 2022/346)
corrected an earlier WOTS argument. The next phase should close these links
in Lean rather than add arithmetic.

## What is argued, not machine-checked

The role bounds and the arithmetic are kernel-checked. The step that each
reduction term **is** the corresponding role game inside the random-oracle
experiment is argued here and not formalized:

1. **Hybrid hops as identical-until-bad.** In the ROM the real and hybrid
   games run on the same tape and differ only once the adversary queries the
   secret point (the master seed for ChaCha, `SK.seed` or `SK.prf` for the
   KDFs, the derived key for the keyed roles). Before that, the secret is
   independent of everything the adversary sees, so `rom_secret_guess`
   applies. The coupling of the two runs (the fundamental lemma) is not
   formalized.
2. **Tweak single use in the lazy run.** `rom_tweak_collision` assumes the
   challenger draws one input per (key, address). `TweakUse.lean` proves this
   for the honest computation against any fixed-width oracle; transporting it
   to the query-tree run (and adding the canonical value at each address the
   verifier touched as an extra challenger draw) is argued.
3. **Hidden values are independent of the adversary's view.** An unrevealed
   chain value or FORS secret enters the adversary's view only through fresh
   oracle answers to requests containing it, which are independent of it
   unless such a request collides with one the adversary made (itself a
   counted event). Resampling it therefore leaves the view unchanged, and
   naming it is a guess. The resampling argument is not formalized.
4. **ITSR with adaptive signing.** `itsr_static` fixes the `q_s` signature
   leaves as independent uniform draws. In the run they are fresh oracle
   answers on distinct inputs (distinct messages), chosen adaptively but each
   uniform when drawn; the forged digest is a fresh answer for a message
   never signed. That the adaptive selection preserves the static bound is
   argued.
5. **Model functions as query trees.** `Model.lean` is monad-generic, so its
   functions run unchanged as query trees; that this run equals the Id-model
   run against the final oracle is proved for logging (`verify_sim`,
   `sign_good`, `keygen_good`) but not for the query-tree monad.

## Assumptions, stated plainly

* Every BLAKE3 role, and ChaCha20 seed expansion, is an independent random
  oracle (one oracle, distinct requests). Keyed BLAKE3 under different keys,
  `derive_key` under different contexts and the XOF are treated as unrelated
  functions even though they share BLAKE3's compression function.
* At most 2^64 signatures per key (the ITSR bound is monotone in q_s; the
  check is at 2^64). Multi-key (one ephemeral key per step): the events are
  per key (`multi_key_reduction`), so N keys multiply the event terms by up
  to N, costing log2(N) bits.
* Adversary cost is counted in oracle queries only; local computation is free.
* Classical adversaries only. The quantum picture is in
  `SPHINCS_QROM_NARRATIVE.md` and is not machine-checked.
