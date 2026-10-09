# DSM BLAKE3 SPHINCS+: classical security level in the random-oracle model

Status: phases 2 and 3 of audit-prep, 2026-10-07, after the frozen tags
`audit-freeze-2026-10-07` and `audit-freeze-2026-10-07-rom` (which this does
not change). Lean 4 core only, no
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

## Phase 3: the hidden-value bridge (kernel-checked, generic)

`RomSym.lean`, `RomHidden.lean`, `RomCoord.lean`. A game is a program whose
challenger requests may contain handles for oracle answers it has not
revealed (`hid i w`: tape entry `i` truncated to `w` bytes); adversary
requests are concrete bytes; `reveal` resolves bytes to the adversary and
marks their handles revealed. Two runs on the same tape:

* real (`xrun true`): the lazy random oracle on resolved requests, as in
  `RomOracle`;
* symbolic (`xrun false`): a request with an unrevealed handle is answered
  from an entry only if the two are syntactically identical; open requests
  (every handle revealed) are compared by their resolutions.

| Statement | Theorem |
|---|---|
| While handle `h` is unrevealed, the symbolic run is the same on every tape that differs only at entry `h` | `strace_inv` |
| If no step's real and symbolic lookups disagree, the two runs are equal | `coupling` |
| A disagreement is either a guess (a request with an unrevealed handle resolves to bytes the run had already fixed) or a collision between two distinct unopened challenger requests | `dis_entry` |
| A guess pins the tape entry of its first unrevealed handle to the bytes at that handle's offset | `guess_pins` |
| Pr[some disagreement] · 2^(8·wmin) ≤ B + Pr[wild guess or unopened collision] · 2^(8·wmin), where B bounds the compatible guess pairs on every tape and "wild" is a guess at a handle narrower than `wmin` bytes or beyond the tape | `hidden_bound` (by `hits_sum`, `coord_hit`) |
| Pr_real[E] ≤ Pr_symbolic[E] + Pr[some disagreement], for every event E | `real_le_sym` |

Controls (`RomChecks.lean`): a correct guess of a hidden value separates the
two runs and is pinned at the right tape entry; a wrong guess leaves them
equal and is still counted as a compatible pair.

What this closes. The resampling step of link 3, as a theorem about every
such program: the symbolic run never reads an unrevealed answer, so a hidden
value is independent of everything the run did until it is revealed, and
the real run departs from the symbolic one only through counted guesses or
collisions.

**Instantiated for DSM's signer (game H1).** `RomSim.lean` gives a
simulation judgment between symbolic programs and query trees (`Sim`, with
rules for bind, the three kinds of step, `if` and `for` loops).
`RomSigner.lean` writes every function of DSM's signer as a symbolic program
and proves that its real run is the model function itself run as a query
tree against the lazy random oracle: `sim_sign`, `sim_kgTail` (key
generation after the seed expansion), and the components (`sim_forsSign`,
`sim_htSign`, `sim_xmssNode`, `sim_htRoot`, ...). Control flow that depends on
a hash output (the h_msg digest, the WOTS digits of a root, the signer's
self-check) reveals that value first. `RomGame.lean` defines the EUF-CMA
game against an interactive adversary (oracle queries, signing queries, a
forgery checked by the model's `verify` with adversary-side requests) as a
query tree and as a symbolic program, proves they agree on every tape
(`sim_game`), and composes: `rom_game_hidden`: Pr[the model's game is won] ·
2^(8n) ≤ Pr[the symbolic game is won] · 2^(8n) + R^N·B/R^N + Pr[wild guess or
unopened collision] · 2^(8n). Game H1 takes the secret key's 3n-byte seed
expansion as three independent uniform n-byte values; the seed hop (ChaCha20
expansion of a secret 32-byte seed) is a separate hybrid step, not part of
this theorem.

What remains open for DSM: (b) B for DSM
(each adversary request is compatible with at most one unopened challenger
request at its address, by tweak single use); (c) that wild guesses do not
occur in DSM's run (output widths are at least n bytes and the budget bounds
the tape); (d) a probability bound on unopened collisions. Address uniqueness
rules a collision out structurally only where two challenger requests differ
in literal bytes at the same offset. Where they differ only in unrevealed
handles (two hidden inputs, or the thash and PRF keys), equal resolutions are
a collision of random-oracle outputs, and that needs its own bound (of the
order of pairs/2^(8n)); it is not yet checked; (e) the step bound S of the
symbolic game from the query budget; (f) the probability of the four
extracted events in the run. The extraction itself is now transported to
the ROM game: `RomEval.lean` reads the lazy oracle's final table as an
oracle function (`oracleOf`) and proves, with a query-tree/logging
correspondence (`QL`, `ql_kgTail`, `ql_verify`) and the model's own logging
lemmas, that on every tape on which the H1 game is won the forgery verifies
against the honest key under that table, so `forgery_extract_exp` yields one
of the four events on the run's own table, with every request of the
verifier's log drawn in the run (`rom_extract`, claim trace C47). Bounding
those four events in the run (canonical collision, WOTS preimage, unrevealed
FORS secret, ITSR covered) is what remains of (f). The WOTS-preimage and
FORS-secret events are now charged to a disagreement step of an extended
game (claim trace C52, C53; see "Secrecy of chain values and FORS secrets"
below), whose probability is again a hidden-value event, but the hypotheses
of that hidden-value bound are not yet discharged for the extended game.
Until (b) to (f) are checked, the numbers above remain conditional on
link 3.

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
   naming it is a guess. The resampling argument is now kernel-checked for
   any challenger written as a symbolic program (phase 3 below). For DSM's
   signer it is instantiated for the WOTS chain values below the signed
   digit and the unrevealed FORS secrets (claim trace C53): a forgery
   hashing one of them is a disagreement step of the extended game. What
   is still argued is the size of that event for the extended game: the
   step and pair-count budgets of `hidden_bound` and its wild-guess and
   unopened-collision term.
4. **ITSR with adaptive signing.** `itsr_static` fixes the `q_s` signature
   leaves as independent uniform draws. In the run they are fresh oracle
   answers on distinct inputs (distinct messages), chosen adaptively but each
   uniform when drawn; the forged digest is a fresh answer for a message
   never signed. That an adaptive selection preserves the static bound is
   now kernel-checked in generic form (`RomSample.lean`: `sample`;
   `RomItsrA.lean`: `itsr_gen`, `itsr_adaptive`, claim trace C48): if a run
   decides from the entries already read which tape entry is the target and
   which are (at most `q`) signature digests, and digests decode to a leaf
   and indices with equal fibers, the covered probability is at most the
   static ITSR numerator over `(G+1)! L^(G+1) T^k`. For DSM's digests the
   equal-fiber property is checked (`RomDigest.lean`: `digest_fiber`, from
   the byte layout of `splitDigest` and the bit order of `base2b`), giving
   `itsr_dsm_128f` (≤ 2^-128) and `itsr_dsm_256f` (≤ 2^-255) per target
   under any adaptive selection of at most 2^64 signature digests (claim
   trace C49). The game-level selection is now checked as well
   (`RomItsrGame.lean`, claim trace C50). On every tape on which H1 is won
   and the ITSR event holds on the run's table, the forgery is charged to a
   unique candidate: the first draw of the verifier's `h_msg` request. That
   draw is adversary-side (the verification runs with the adversary's
   oracle), because a challenger-side `h_msg` draw is the signing request of
   a signed message, and the request encoding binds the message: its prefix
   `R ‖ PK.seed ‖ PK.root` has fixed width `3n`, so equal requests have equal
   messages (`hreqR_msg`; no collision term is needed for this step). The
   candidate index `j` counts adversary-side `h_msg` draws, so there are at
   most `JA` candidates (`JA ≤ q_h + 1`, repeated queries counted once since
   only first draws are candidates). The signature digests are the
   challenger-side `h_msg` draws, at most `q`; the selection of slots is
   decided from the tape prefix (`slotJ_pred`). `itsr_game_128f` /
   `itsr_game_256f` then bound the won-and-covered tapes by `JA · 2^-128` /
   `JA · 2^-255`. These theorems are conditional on three budget
   hypotheses (at most `N` draws, at most `q ≤ 2^64` challenger `h_msg`
   draws, at most `JA` adversary `h_msg` draws, on every tape) and are
   restricted to the event `NoRG`: no signing request was first drawn by
   the adversary. The complement of `NoRG` is now charged to the
   hidden-value event (`RomProv.lean`, claim trace C51): on every tape whose
   symbolic run of DSM's game has no disagreement step, `NoRG` holds
   (`norg_of_nodis`), so `itsr_game_hid_128f` / `itsr_game_hid_256f` bound
   the won-and-covered tapes by `JA · 2^-128` / `JA · 2^-255` plus the
   `anyDis` tapes, which `rom_game_hidden`'s hidden-value bound already
   counts. The proof is a Hoare-style invariant over the symbolic run
   (origin, protection/disclosure, order), discharged once per request
   constructor DSM's signer issues; see "Provenance invariant" below. Still
   argued: that the budget hypotheses follow from the adversary's query
   budget.
5. **Model functions as query trees.** `Model.lean` is monad-generic, so its
   functions run unchanged as query trees; that this run equals the Id-model
   run against the final oracle is proved for logging (`verify_sim`,
   `sign_good`, `keygen_good`) but not for the query-tree monad.

## Provenance invariant (phase 3, checked)

`RomProv.lean` defines a judgment `J P Pre Q` over the symbolic run: from a
state satisfying the invariant `Inv` and `Pre`, if no step of `P` is a
disagreement step, the final state satisfies `Inv`, its entries extend the
initial ones, and `Q` holds. `Inv` has three parts.

* **Origin.** Entries 0-2 are the coins SK.seed, SK.prf and PK.seed. Every
  handle in an entry refers to an existing entry. Adversary entries carry
  no handles.
* **Protection and disclosure.** Every revealed handle is `Safe`: its entry
  does not mention SK.seed or SK.prf, so neither coin nor a key derived
  from them (the WOTS/FORS PRF key, the PRF-msg key) is ever revealed. A
  revealed message randomizer R has its signing request h_msg(R, PK.seed,
  root, m) already drawn challenger-side. Disclosure is checked for every
  legitimate challenger operation: revealing the public key, the digest,
  the intermediate roots and the signature, and every adversary query.
  The latter can only open an entry whose handles are all revealed.
* **Order.** No adversary entry precedes a challenger h_msg entry with the
  same resolution.

The step lemmas (`step_askC`, `step_askA`, `step_reveal`) preserve `Inv` on
a disagreement-free trace. The request-level lemmas cover:

* `ask_tk`, `ask_dPrf`, `ask_dReq`, `ask_rq` for the key derivations and the
  randomizer;
* `J.hmsg` for the signing request;
* `j_thash`, `j_prf` for the hash and PRF calls.

Each twin of the signer, and the adversary's verification, is then checked
by structure. Together they give `sym_game`: on a disagreement-free run,
every signed message's signing request has a challenger entry.
`norg_of_nodis` transports this to the real run through `coupling` and
`sim_game`.

The judgment separates the adversary *learning* a protected value from
*computing* a request equal to a hidden one. The first is excluded by
`Inv`. The second is a disagreement step, i.e. an event of the
hidden-value bound.

This invariant does not cover the WOTS-preimage and FORS-secret
extraction events. A second invariant, below, treats them, with the chain
values and FORS secrets as the protected handles.

## Secrecy of chain values and FORS secrets (phase 3, checked)

Three steps, kernel-checked, Lean core, core axioms only. Nothing here
bounds a probability yet; the result is an inclusion of events on every
tape.

**Path-located extraction** (`RomPath.lean`, claim trace C52). A verifying
forgery under the honest key gives a canonical collision in the verifier's
log, or `WotsPath`, or `ForsPath`, or ITSR coverage (`forgery_extract_path`).
`WotsPath` locates the WOTS event on the verifier's path. At hypertree layer
`k`, at the position the forged digest selects, the verifier's log contains
the thash request on the honest chain value at a step below the digit the
honest key signs there. `ForsPath` locates the FORS event the same way. The
verifier's log contains the leaf request on the honest FORS secret at an
index no signed message selects.

**The extended game H1'** (`RomExt.lean`, claim trace C52). After H1 ends,
the challenger recomputes, recursively from the honest seeds:

* the honest WOTS public keys on the hypertree path of the forged digest,
  which draws every honest chain value up to the top;
* the honest FORS leaves at the forged digest's indices;
* (`extTail`) the complete honest FORS key of the forged digest (every FORS
  tree and the roots compression), and the complete honest XMSS tree at every
  layer of the forged path. Every canonical request at an address of the
  forgery's verification path is thereby an actual challenger draw (no
  zero-fallback canonical values).

The extension's draw count is a fixed function of the parameters. For
SPHINCS+-128f it is at most 117,605 draws (under 2^17), about one
signature's worth of hashing.

The forged digest is recomputed with an adversary-side `h_msg` request. The
extension runs after the adversary has stopped, so it does not change the
adversary's view. It only appends draws: the main game's draws are a prefix
of H1' (`pre_ext`), and the output and the key are those of H1 (`out_ext`,
`finKey_ext`; bundled as `ext_conservative`). The four events are read on H1''s final table (`finO'`), and
`rom_extract_ext` gives them on every tape on which H1 is won.

**Secrecy invariant** (`RomSecrecy.lean`, `RomSecGame.lean`, claim trace
C53). The judgment `J2 P Pre Q` works over disagreement-free symbolic runs
of H1' whose final table extends a fixed table `D`. Its invariant `Inv2` has
four parts:

* **Origin.** As in `Inv`.
* **Distinctness.** Two entries past the coins never resolve to the same
  request. On a disagreement-free run a new entry is appended only when no
  entry, opened or not, has its resolution. So every entry's value is the
  final table's answer to it (`agree`).
* **Protection and disclosure.** A revealed handle never mentions SK.seed
  or SK.prf, as before. In addition, it is never:
  * a *low* WOTS chain value, meaning the honest value at a step below the
    digit the honest key signs at that position (`LowChain`; the honest
    messages are those of the final table);
  * a FORS secret, unless some challenger signing request's digest selects
    its index (`SigD`, `Sel`).
* **Signing requests.** Every challenger `h_msg` entry is the signing
  request of a message signed in the run, with its randomizer's PRF-msg
  entry.

The step lemmas and the per-request lemmas cover every operation of
DSM's H1'. Each item names its lemmas:

* the step lemmas `step_askC2`, `step_askA2`, `step_reveal2`;
* the key derivations, the randomizer and the signing request (`dTk_ask`,
  `dPrf_ask`, `dReq_ask`, `rq_ask`, `hq_ask`);
* thash and PRF;
* the signer's twins, checked relationally against the `Id` model on the
  final table: chains, WOTS, XMSS, FORS, hypertree (`jr_*`);
* key generation (`j2_kgTail`);
* signing (`j2_sign`);
* the play loop (`j2_play`). Its precondition is the condition, on the
  rest of the run, that every message it will sign is in the final signed
  list;
* the adversary's verification (`ja_verify`). Every request in the Id
  model's verifier log ends with an *open* entry, i.e. one all of whose
  handles are revealed;
* the extension (`j2_ext`). It leaves the honest chain entries up to each
  digit on the path and the honest FORS leaf entries at the digest.

`sec_game` collects these for the whole run. The final step (`no_wotsPath`,
`no_forsPath`) runs as follows:

1. The verifier's request on a low chain value has the resolution of the
   extension's chain entry one step above it.
2. Distinctness makes them one entry.
3. That entry is open, so the low value is revealed, which `Inv2` excludes.

The FORS case is the same, with the leaf entry. A revealed FORS secret
has a selecting signing request, which via the final table and the
signing-request clause gives `RevealedBy` for a signed message.

`no_paths` transports this to the real run through `coupling` and
`sim_game'`. `rom_extract_sec` then shows that on every tape on which H1 is
won, one of three things holds on H1''s table:

* a canonical collision in the verifier's log;
* the forged digest is ITSR-covered by the signed messages;
* `anyDis` holds for H1' (a disagreement step of its symbolic run).

As in the provenance invariant, *learning* a protected value is excluded
by the invariant, and *computing* a request equal to a hidden one is a
disagreement step.

**Coverage transfer and the assembled count** (`RomCover.lean`, claim
trace C54). H1''s table answers every draw of H1 as H1's table does
(`fin_agree`). Every request the covered event reads was drawn in H1:

* the forgery's digest request is in an accepting verifier's log
  (`verify_log_hmsg`);
* for each signed message, its PRF-msg key derivation, randomizer and
  signing requests are in the signing run's log (`sign_log_dReq`,
  `sign_log_rReq`, `sign_log_mem`), all of which is drawn (`game_signlog`).

So coverage on H1''s table is coverage on H1's (`cov_transfer`). With
`rom_extract_sec`, on every tape on which H1 is won (`rom_win_split`), one
of these holds:

* a canonical collision on H1''s table;
* `CovG`;
* `anyDis` of H1'.

Summed over tapes, with `itsr_game_hid_128f` / `_256f` and the inclusion
of H1's disagreement steps in H1''s (`anyDis_ext`), this gives
`rom_win_128f` / `rom_win_256f`, as counts of tapes scaled by `2^128` /
`2^255`:

    #won · 2^128 ≤ #canon-collision(H1') · 2^128 + JA · R^N
                   + 2 · #anyDis(H1') · 2^128

This is conditional on the three budget hypotheses of the ITSR theorem:
at most `N` draws, at most `q ≤ 2^64` challenger `h_msg` draws, and at
most `JA` adversary `h_msg` draws, on every tape.

`hidden_bound` is generic in the symbolic program, so it applies to H1' as
it stands (`rom_ext_hidden`). With `256^n = 2^128` for SPX128f, this gives
`rom_win_hidden_128f`:

    #won · 2^128 ≤ #canon-collision(H1') · 2^128 + JA · R^N
                   + 2 · R^N · B + 2 · #wildColl(H1') · 2^128

`rom_win_hidden_256f` is the same against `2^256`, with the ITSR term
doubled. Both are conditional on the ITSR budget hypotheses and on two
hypotheses of `hidden_bound` for H1':

* a step bound `S` on its symbolic traces;
* a pair-count budget `B`.

**Why `B` is not yet useful, and the fresh-step bound** (`RomFresh.lean`,
claim trace C56). `pairCount` charges every (step, compatible entry) pair.
Every signature recomputes shared hypertree nodes, so one closed challenger
request is asked once per signature. Each of those asks is charged again
against every adversary entry at its address. For DSM, `B` therefore grows
like (signing steps) × (adversary entries per address), far above `2^128`.
Tweak single use alone does not change that.

`RomFresh.lean` bounds the same event, `anyDis`, while charging fewer
steps. Each item names its lemmas:

* Before the first disagreement step, entries past the initial ones
  resolve to distinct requests (`trace_distK`).
* So the first disagreement step is an adversary step, or a challenger
  step whose symbolic lookup appends a new entry (a fresh step). The only
  exception is when two initial entries collide: event `initColl`
  (`first_dis_elig`). A fresh challenger step occurs at most once per
  distinct challenger request.
* `hidden_bound_split` charges only eligible steps that also satisfy a
  tape-independent predicate `Φ`. `Φ` is assumed to hold at every step
  with no earlier disagreement, so nothing is narrowed without proof.
* It splits the probes by the width of the pinned handle. Pins narrower
  than `W` cost `1/256^wmin` each; pins of width at least `W` (the 32-byte
  keys) cost `1/256^W`:

      #anyDis · 256^W ≤ R^N · B_lo · 256^(W-wmin) + R^N · B_hi
                        + #(wildColl ∨ initColl) · 256^W

  `B_hi ≤ S^2` always (`pairCountF_le_sq`), which costs `S^2 / 2^256`.

What remains for a useful `B_lo` is to discharge `Φ` for H1'. The intended
`Φ` has three parts:

* *canonical uniqueness*: two challenger entries with the same literal
  skeleton are one entry;
* *freshness*: a fresh challenger request's skeleton is new;
* *shape families*: every challenger request belongs to one of a few
  families.

With `Φ`, narrow pins occur only in pairs involving an adversary draw,
each charged once, so `B_lo ≤ 2c · A` (c ≈ 10 families, A adversary
draws). Discharging `Φ` needs a request-level dataflow invariant: each
input handle of a challenger thash request is the entry of its canonical
child request. Resolution-level canonicity is not enough, because output
collisions among the honest values are expected at DSM's scale. It also
needs `Φ` at intermediate states, so the judgment must cover every
pre-step state of a disagreement-free prefix, not only end states.

**The structural invariant of H1'** (`RomStruct.lean`, claim trace C57).
This is the request-level dataflow invariant described above, proved for the
whole extended game. It is stated about the symbolic dataflow, not about
values, and it holds at every pre-step state of every disagreement-free
prefix, on every tape. The judgment is `JS`:

* It is prefix-closed. Every pre-step state reached without an earlier
  disagreement satisfies the invariant `InvS`. That includes the states
  inside WOTS chains, the XMSS and FORS authentication walks, the hypertree
  layers, signing, the forgery's verification and the extension.
* Each step meets its obligation (`StepOK`). A challenger request belongs to
  one of DSM's families (`FamOK`): the three key derivations, a PRF request,
  the randomizer, the signing request, or a *structured* thash request. A
  structured thash request has an in-range address literal, the tweak-key
  entry as its key, and as its k-th input the handle of the k-th canonical
  child of its address (`kids`), to any depth. That handle *is* the
  challenger entry of the child request (not merely an entry with the same
  resolution), and every canonical child has the address as its DSM parent
  (`DSMOK`, `par`).
* A revealed handle is never protected, i.e. never an entry that mentions
  SK.seed or SK.prf.
* A revealed handle has *provenance* (`AncOK`): if it is a challenger thash
  or PRF entry, every DSM ancestor of its address already has a structured
  challenger entry. See C60 below.

`InvS` also keeps DistK (distinct resolutions past the coins), so
structured requests are unique per address (`struct_unique`). As a
consequence, two handles that resolve to the same canonical node are one
handle (`kidOK_unique_th`). Verification uses this to match the
recomputed layer roots with the signer's. The game-level statement is
`game_struct`.

**The narrow-pin count of H1'** (`RomPhi.lean`, claim trace C58). Here
`Φ` is derived from `game_struct`, and `B_lo` is bounded.

* `Φ` (`PhiP`) is tape-free. Every challenger entry has one of DSM's request
  shapes. Narrow-shaped entries (thash, the key derivations, the signing
  request) have pairwise distinct literal skeletons (handle indices erased).
  A challenger request's skeleton is shared only by its own entry. A PRF or
  randomizer request's 32-byte key is unrevealed. `game_phiB` proves `Φ` at
  every step of H1' with no earlier disagreement, on every tape.
* A narrow-shaped request compatible with given bytes has a skeleton
  determined by those bytes (`skel_of_compat`). This is what bounds the
  skeletons compatible with one pinned handle.
* Narrow pins are classified exhaustively for `anyDis`'s probes (`np_class`):
  * at an adversary step, the pin is against a coin or a narrow-shaped
    challenger entry compatible with the query;
  * at a challenger step, it is against an adversary entry;
  * challenger-vs-challenger narrow pins are impossible.
* The count (`narrow_count`):
  * an adversary step carries at most four narrow pins (three coins and one
    skeleton-determined entry);
  * an adversary entry is pinned by at most one fresh challenger step,
    because a second would share the first's skeleton, contradicting
    freshness (`fresh_entry`).
  * So `B_lo ≤ 5·AA`, where `AA` bounds the adversary steps of H1'.
  * Wide pins keep `B_hi ≤ S^2`.

The bound for H1' (`rom_ext_struct`):

    #anyDis(H1') · 2^256 ≤ R^N · 5·AA · 2^(256-8n) + R^N · S^2
                          + #(wildColl ∨ initColl)(H1') · 2^256

Composed for SPHINCS+-128f (`rom_win_struct_128f`):

    Pr[won] ≤ Pr[canonical collision on H1''s table] + JA/2^128
              + 10·AA/2^128 + 2·S^2/2^256 + 2·Pr[wildColl ∨ initColl in H1']

This is conditional on the ITSR budget hypotheses, the step bound `S` and
the adversary-step bound `AA`.

Two caveats:

* *Disagreements counted elsewhere.* The narrow-pin count covers
  disagreements caused by guessing a hidden `n`-byte handle. Disagreements
  caused by two independently sampled values coinciding are `collC`, in the
  `wildColl` term, with collisions among the coins (`initColl`). Both are
  bounded below (C59).
* *SPHINCS+-256f.* There all handles are 32 bytes, so the split brings
  nothing, and the wide term `S^2/2^256` is not small against the 256f
  target. 256f needs a wide-class count of the same kind, and also a
  refinement of the `N^2/2^256` key-collision terms of C59 and C60, which are
  of the same order (see C62). Both are done in C63 and C64.

**Collisions of independently sampled values** (`RomColl.lean`, claim
trace C59). The wild/collision event is needed only at the first
disagreement step. `hidden_bound_splitP` therefore restates the bound with
the event restricted to steps with no earlier disagreement (`wildCollP`).
At those steps the structural invariant holds:

* *No guess is wild* (`wildE_false`). Every handle of every entry and
  request is an existing entry of width `n` or 32, so it is at least
  `wmin = n` wide and below `N` (given `S ≤ N`).
* *An unopened collision is a key collision* (`collC_key`). Two distinct
  hidden challenger requests with one resolution can be:
  * both narrow-shaped: impossible, because their skeletons agree, so
    `famOK_skel_unique` makes them one request;
  * otherwise, of mode 1. Then they are keyed by two of the three 32-byte
    key entries (tweak key, PRF key, PRF-msg key). If the key entries
    differ, their values collide. If they are the same entry, the two
    requests coincide, because a PRF request is determined by key and
    address, and the randomizer by key and message.
* *Initial collisions* (`initColl_coin`) are two coins agreeing modulo
  `256^n`.

So the event is a tape collision (`coll_event`): two of the first three
tape entries agree modulo `256^n`, or two entries below `N` agree modulo
`256^32`. Its count is `3/2^(8n) + N^2/2^256` of the tapes (`tape_coll`,
via `hits_sum`).

Composed for SPHINCS+-128f (`rom_win_coll_128f`):

    Pr[won] ≤ Pr[canonical collision on H1''s table]
              + (JA + 10·AA + 6)/2^128 + 2·(S^2 + N^2)/2^256

This is conditional on:

* the ITSR budget hypotheses;
* the step bound `S ≤ N`, with `3 ≤ N`;
* the adversary-step bound `AA` of H1'.

**The canonical-collision count** (`RomStruct.lean`, `RomCanon.lean`, claim
trace C60). This removes the last event term of H1 that was not a count.

*Provenance.* `InvS` now also requires `AncOK` for every revealed handle (see
C57). Reveals discharge it as follows:

* The signer reveals a signature only after recomputing its root from it
  (`js_xmssPkFromSigC`, `js_forsPkFromSigC`). The root's structure covers
  every handle of the signature (`cov_xsig`, `cov_slots`), by descent along
  the canonical children (`ancCov_reach`).
* The message it signs, the recomputed roots and the public root are roots
  (`par = none`): XMSS tree tops and the FORS roots compression.
* An adversary lookup that opens a challenger thash entry inherits provenance
  from the entry's revealed first child (`ancOK_open`). A PRF entry is never
  open, since its key is protected.

*Consequence* (`ask_struct`). A structured challenger request is always
answered by its own challenger entry. If it has an unrevealed handle, no
adversary entry matches it. If it is open, its first child is revealed, so by
provenance the challenger already holds a structured request at its address.
That request is this one (`struct_unique`). So the canonical value at every
address is a challenger draw, never an adversary draw.

*Value canonicity* (`struct_val`). On the final table, a structured request at
`b` is the canonical request `thashReq tk b (canon b)`. This is by induction,
from `canon_kids`: the canonical input is the concatenation of the canonical
children's honest values. It needs FORS height at least one, and XMSS nodes
with keypair 0 (`struct_kp2`).

*Path* (`verifyLog_path`). Every thash request in the verifier's log is at an
address of the forged path that the verifier's digest selects: a root (the
FORS roots compression, a layer's tree top) or a canonical descendant of one.
The extension's digest is the verifier's (`ExtF`, `dig_eq`). `ExtS` gives a
structured challenger entry at every root, and by descent (`kidAt_reach`) at
every path address.

*Event inclusion* (`canon_split`). On a disagreement-free run of H1', a
canonical collision gives one of two things:

* an adversary entry and a structured challenger entry at one address
  literal, with equal truncated values. The verifier's request is an entry
  (it is opened). It is not a challenger thash entry, since the only one at
  that address is canonical (`struct_unique`).
* a 32-byte key coincidence. The verifier's request is answered by a PRF or
  randomizer entry whose key equals the tweak key.

*Charging* (`pairW`, `pair_hit`). The pair is charged at the later of its two
creations, whose value is a fresh tape coordinate:

* an adversary request appends an entry at an address that already has a
  challenger thash entry. It is pinned against that entry's value.
* the first challenger thash entry at an address appears after an adversary
  entry there. It is pinned against the adversary entry's value.

The earlier value is fixed by the prefix, whatever its visibility. It may be
drawn before the adversary request, drawn but hidden, or already observed:
the later draw is fresh in all three cases, so no hidden-target argument is
needed. The case that would need one is the adversary drawing the canonical
request itself before the challenger. Provenance excludes it: the children of
an open canonical request were revealed only after its challenger entry
existed. The pair weight and target do not depend on the pinned coordinate
(`pairW_inv`, `pairTg_inv`, via `strace_inv`).

*Count* (`pair_count`). There is at most one pair per adversary step, since an
address gets at most one fresh challenger thash entry. So:

    #(canon ∧ ¬anyDis)(H1') · 256^(n+32) ≤ R^N · AA · 256^32 + R^N · N^2 · 256^n

(`canon_count`). Disagreement tapes are already counted, so the split
`rom_win_split'` keeps the factor 2 on `anyDis`. Composed for SPHINCS+-128f
(`rom_win_full_128f`):

    Pr[won] ≤ (JA + 11·AA + 6)/2^128 + (2·S^2 + 3·N^2)/2^256

This is conditional on:

* the ITSR budget hypotheses;
* the step bound `S < N`, with `3 ≤ N`;
* the adversary-step bound `AA` of H1'.

**The query budget** (`RomBudget.lean`, claim trace C61). This derives `S`,
`N`, `AA`, `JA` and `q` from the adversary's query budget, with no further
budget hypothesis.

*Budget* (`Budget A qh qs`). On every path of the adversary's strategy tree:

* each hash query (`hq`) consumes one unit of `qh`. Repeated queries are
  charged again; the run memoizes them, so this only over-counts;
* each signing query (`sq`) consumes one unit of `qs`, legal or not. An
  illegal query costs the game nothing;
* the final output (`out`) is free.

Challenger requests (key generation, signing, the extension) are not charged
to the adversary. They are bounded per routine instead.

*Cost* (`Cost P K A C`). On every tape and from every state, the symbolic
trace of `P` has at most `K` steps, at most `A` of them adversary steps. Both
runs, real and symbolic, append at most `K` entries, at most `A` adversary
entries and at most `C` challenger `h_msg` entries.

Costs compose (`Cost.bind`, `Cost.forIn`, `Cost.ite`). They are computed in
closed form for every routine of the signer, the verifier, key generation and
the extension (`cost_sign`, `cost_verify`, `cost_kgTail`, `cost_extW`). For
the strategy tree, `cost_playS` is by induction under `Budget`.

*Steps vs. draws.* Entries are the run's distinct draws. A memoized repeat
appends none, and every step appends at most one (`strace_ents`). So the
draw count is bounded by the step count. `N` bounds H1's draws, which equal
its entries (`runG_draws`, via `sim_game`). `S` bounds H1' trace steps, and
entries at every step, as the collision count needs.

*Classification.* Every adversary step of H1' is an adversary-oracle request,
from one of three sources:

* the adversary's own hash queries, at most `qh`;
* the final verification. It runs the model's `verify` on the adversary
  oracle (`advP`), at most `verC` requests;
* the extension's `h_msg` request on the forged message, which is one.

So `AA ≤ qh + verC + 1`, **not** `AA ≤ qh`. The verifier's and the extension's
requests are adversary-side steps of H1' that the adversary did not choose,
and the collision count must charge them. Similarly, `JA ≤ qh + verC` (H1 has
no extension), and the challenger `h_msg` draws number at most `qs`.

*Formulas* (`stepB`). H1' has at most

    K' = kgC + 1 + qh + qs·(signC + 1) + verC + extC

steps. The terms are: key generation, the public-key reveal, the adversary's
queries, per signing query the signer plus the signature reveal, the final
verification, and the extension. Then:

* `S = K' + 3`: the coin state holds three entries;
* `N = S + 1`.

For SPHINCS+-128f the per-routine bounds evaluate to:

| Routine | Steps |
| --- | --- |
| kgC | 4,497 |
| signC | 370,401 |
| verC | 11,872 |
| extC | 117,606 (117,605 requests and one reveal) |

So (`stepB_128f`):

    JA = qh + 11872,  AA = qh + 11873,  q = qs,
    S  = qh + 370402·qs + 133979,  N = qh + 370402·qs + 133980.

In the form `N = N_KG + qs·N_Sign + qh + N_Verify + 117605 + C`:

* N_KG = 4,497;
* N_Sign = 370,402;
* N_Verify = 11,872;
* C = 6: the extension's reveal, the public-key reveal, the three coin
  entries, and one for `S < N`.

These are step counts, which over-count distinct draws whenever requests
repeat.

*Theorem* (`rom_win_budget_128f`). For every adversary with `Budget A qh qs`
and `qs ≤ 2^64`, the model's own H1 game satisfies (multiplied out in Lean)

    Pr[won] ≤ (12·qh + 142481)/2^128 + (2·S^2 + 3·N^2)/2^256

with `S` and `N` as above. At `qh = qs = 2^64` this is about 2^-60.4: the
linear term dominates, and the quadratic term is about 2^-88.7. These
evaluations are arithmetic outside Lean.

What this does not yet cover:

* this is game H1: honest key generation from three independent coin entries,
  not from the 32-byte seed;
* the bound is per key (see the multi-key note below);
* the random-oracle and tape assumptions of C54–C60 still apply.

**SPHINCS+-256f, first composition** (`RomBudget.lean`, claim trace C62;
superseded for 256f by C64).
The same ingredients compose for 256f (`rom_win_full_256f`). There `n = 32`,
so every pin and collision term is against `2^256`, and the ITSR term is
`JA/2^255`:

    Pr[won] ≤ (2·JA + 11·AA + 6 + 2·S^2 + 3·N^2)/2^256

With the query budget (`rom_win_budget_256f`, `stepB_256f`):

| Routine | Steps |
| --- | --- |
| kgC | 17,185 |
| signC | 1,704,961 |
| verC | 17,523 |
| extC | 364,152 |

This gives:

    JA = qh + 17523,  AA = qh + 17524,
    S  = qh + 1704962·qs + 398864,  N = S + 1,
    Pr[won] ≤ (13·qh + 227816 + 2·S^2 + 3·N^2)/2^256

This bound is birthday-limited:

* at `qh = 2^64`, `qs ≤ 2^20`, it is about 2^-125.7;
* at `qh = qs = 2^64`, it is about 2^-84.3;
* the linear term is about 2^-188 in both cases.

So it is not the 256-bit-level statement (about `qh·2^-252`) that the ITSR
term alone would give. The quadratic part has three sources, all of the same
order:

* `2·S^2`: wide pins (`B_hi ≤ S^2`, C58);
* `2·N^2`: the 32-byte key collision of C59 (`coll_event`);
* `N^2`: the 32-byte key coincidence of C60 (`canon_split`).

The last two are collisions among the three 32-byte key entries (tweak key,
PRF key, PRF-msg key), but the C59 and C60 events forgot which entries they
are, and were counted as any two of `N` tape entries. A wide-pin count alone
would change only the constant. These evaluations are arithmetic outside Lean.
C63 and C64 remove all three quadratic terms.

**Key collisions** (`RomKey.lean`, claim trace C63). This is one shared event
for C59 and C60.

*Event inclusion.* Both events now name the colliding entries.

* `collC_key` (C59) returns two *key entries* (`KeyEnts`): challenger entries
  whose requests are among the three key derivations (`keyReqs`). The other
  branches do not survive:
  * two narrow-shaped requests are skeleton-unique;
  * two requests keyed by the same entry coincide.
* `canon_split` (C60) does the same for its 32-byte branch. That branch was a
  PRF or randomizer entry whose key value equals the tweak key's; the
  structured branch contradicts `struct_unique`.

No case of either event leaves a collision between other 32-byte values.

*The event* (`KeyColl`). A step appends a challenger key entry at an
unrevealed position. Its coordinate agrees, modulo `256^32`, with an existing
challenger key entry. Two lemmas lift the inclusions from key entries of a
disagreement-free prefix to `KeyColl`:

* `keyColl_of_fin`: the later entry's creation step has an unrevealed
  position, by `InvS`;
* `coll_event_key` and `canon_split_key` then give the C59 and C60
  inclusions.

*Count* (`key_count`). The pair is charged at the later key's creation. That
creation is a fresh tape coordinate; the earlier key's coordinate is fixed by
the prefix (`keyW_inv` and `keyTg_inv`, via `strace_inv`). The PRF-msg key's
creation position varies with the run, but it is selected by the prefix,
without its own draw.

There are at most three charged pairs per tape (`keyW_total`):

* a request is appended at most once (`keyW_unique`, `ch_once`);
* a key is never charged against itself (`keyW_diag`);
* of two keys only the later is charged (`keyW_anti`).

So `#KeyColl · 256^32 ≤ 3·R^N`. The refined counts are:

* `coll_count_key`: `#(wildColl ∨ initColl)(H1') · 256^(n+32) ≤
  3·R^N·256^32 + 3·R^N·256^n`, with coin collisions counted separately;
* `canon_count_key`: `#(canon ∧ ¬anyDis) · 256^(n+32) ≤ R^N·AA·256^32 +
  3·R^N·256^n`.

**The wide-pin count and the linear 256f bound** (`RomWide.lean`, claim trace
C64).

*The obstacle.* A probe at a challenger step can compare a hidden PRF or
randomizer entry with an *open* thash request, or the reverse. The two shapes
agree in mode, context and output length, so they are syntactically
compatible whenever the thash input ends in the PRF literal. For example, the
adversary can sign a message equal to the tail of a revealed thash input. In
the worst case over tapes there are `O(S)` such probes, so they cannot be
charged to adversary steps.

Each such probe pins the hidden PRF or PRF-msg key against the tweak key's
value, which is legitimately disclosed. A hit is therefore a key collision.

*Filtered hidden-value bound* (`hidden_bound_Q`). The bound takes a
tape-free probe filter `Ψ` in one width class:

* filtered probes are not counted;
* a filtered probe that hits is charged to an event `E` (`dis_pointQ`).

Probes still pin the first *unrevealed* handle of the hidden request. Disclosed
values (the tweak key once revealed, adversary bytes) are never pinned. They
are only the targets.

For H1':

* `Ψ = psiB` (`KeyTh`): a challenger step pairing a PRF-shaped request with a
  thash-shaped one;
* `E = KeyColl` (`game_keyTh`, from `InvS`): the PRF-shaped request is keyed
  by the PRF or PRF-msg key, and the thash-shaped one by the tweak key;
* `Φ = phiW` (`PhiW`, from `InvS` via `game_phiW`): `PhiP`, plus literal
  uniqueness of challenger entries past the coins, plus PRF-shaped requests
  keyed by the PRF or PRF-msg key.

*Classification* (`pin_class_w`, exhaustive). Every counted probe falls into
one of two cases:

* *An adversary step against a challenger entry.* The entry is a coin, a
  narrow-shaped entry compatible with the query, or a PRF-shaped entry
  compatible with the query.
* *A challenger step against an adversary entry.* The request is narrow-shaped
  or PRF-shaped.

All other combinations are impossible or filtered:

* skeleton uniqueness rules out narrow-vs-narrow;
* mode mismatch rules out PRF against a key derivation or the signing request;
* `Ψ` filters PRF against thash.

*Count* (`wide_count`). At most nine probes per adversary step:

* per adversary step, at most six (`adv_step_w`): three coins, one
  narrow-shaped entry (its skeleton is fixed by the query), and one
  PRF-shaped entry per key (its literal is fixed by the query);
* per adversary entry, at most three fresh challenger steps
  (`chal_entry_w`): one narrow-shaped and one PRF-shaped per key, since a
  request is fresh only once.

So:

    #anyDis(H1') · 2^256 ≤ R^N·9·AA + #(wildColl ∨ initColl)·2^256 + #KeyColl·2^256

(`rom_ext_wide`, for any variant, all pins against `256^n`).

*Composed for SPHINCS+-256f* (`rom_win_lin_256f`):

    Pr[won] ≤ (2·JA + 19·AA + 21)/2^256

There is no `S^2` or `N^2` term: `S` and `N` enter only as the step bound and
the tape length. With the query budget (`rom_win_budget_lin_256f`):

    Pr[won] ≤ (21·qh + 368023)/2^256

This holds for every adversary with `Budget A qh qs` and `qs ≤ 2^64`. At
`qh = 2^64` it is about 2^-187.6, for any `qs ≤ 2^64`, evaluated outside
Lean. It is linear in the hash-query budget and independent of `qs`, apart
from the ITSR condition `qs ≤ 2^64` and the tape length.

For SPHINCS+-128f the C61 bound is kept. The filtered bound would price every
pin at `2^-128` and raise the `AA` coefficient there, while the quadratic
terms of C61 are already about 2^-88.7 at `qh = qs = 2^64`.

What this does not yet cover:

* this is game H1: honest key generation from three independent coin entries,
  not from the 32-byte seed;
* the bound is per key;
* the random-oracle and tape assumptions of C54–C60 still apply.

**The seed hop and the real 256f game** (`RomSeed.lean`, claim trace C65).

*The expansion.* The implementation (`crates/dsm-sphincs`
`generate_keypair_from_seed`) runs
`ChaCha20Rng::from_seed(seed32).fill_bytes(sk[..3n])` and splits the output
as SK.seed ‖ SK.prf ‖ PK.seed. The model's `generateKeypair` is the same, with
one request `⟨3, "ChaCha20Rng", [], seed32, 3n⟩`. Mode 3 is used by no BLAKE3
role. On tape coordinate `x` the answer is `be (3n) x`. It is uniform over
`3n` bytes only if `256^(3n)` divides the tape range `R`. The real-game
theorem therefore takes `R = c·256^(3n)·256^m`, which H1 allows since it only
needs `c > 0`. Given that, the three slices are exactly three independent
uniform `n`-byte values (`expand_slices_sum`, `be_split3`). No PRG or
"ChaCha is random" step is used beyond the oracle model itself.

*A dependency H1 did not model.* H1's coins are oracle-table entries with
requests `⟨999, "DSM/rom/coin", [], coin, n⟩`, and the adversary may query
any request. Coin 2 is PK.seed, which is public. So in H1 the query
`⟨999, "DSM/rom/coin", [], PK.seed, n⟩` returns PK.seed, while in the real
game it returns fresh bytes: H1 is distinguishable from the real game. The hop
handles this by renaming, not by a bad event:

* the real adversary `A` is mapped to `renA A`, which shifts every request of
  mode ≥ 999 up by one mode (`ren`);
* `ren` is injective and preserves output lengths;
* it is the identity on DSM's modes 0–3 and never produces a mode-999 (coin)
  request;
* the budget is preserved (`budget_ren`).

The honest routines and the verifier never ask a request of mode above 2
(`m_kgTail`, `m_sign`, `m_verify`), so the renaming leaves them unchanged
(`RenR.refl`, `play_ren`).

*Coupling* (`run_couple`, `win_couple`). Take a real tape `x :: rest` and an
H1 tape `a :: b :: c :: rest` with `x = (a·M + b)·M + c` (`M = 256^n`). The
real run, with the expansion entry first, and H1 with `renA A`, with the
three coin entries first, run identically:

* the tables agree after the first entries, with a table offset of 2 and
  adversary requests renamed;
* each answer is the same tape coordinate.

This holds until H1's table holds the expansion request of the seed
(`SeedBad`). One oracle serves every mode, so cross-domain queries are part
of the coupling: a request matches an entry only if the whole request is
equal.

*Seed guess* (`seedBad_guess`, `seedGuess_qh`). On a fixed tape, H1 does not
depend on the seed. `SeedBad` makes the seed one of the inputs of H1's mode-3
entries. Those entries come only from the adversary's hash queries (`play_m3`,
`game_m3`, `run_cnt`), so there are at most `qh`. Over `2^256` seeds this
costs `qh/2^256` (`guess_bound`). The guess list holds every mode-3 input,
whatever its context or output length.

*The hop* (`seed_hop`):

    Pr[real won] ≤ Pr[H1 won by renA A] + qh/2^256

Real tapes have `K+1` coordinates and H1 tapes `K+3`. The reindexing is
`runR_mod`, `runG_mod`, `sum_mod_eq` and `sum_cube`.

*SPHINCS+-256f, real key generation* (`real_win_256f`). Composed with
`rom_win_budget_lin_256f` for `renA A`:

    Pr[won] ≤ (22·qh + 368023)/2^256

This holds for every adversary with `Budget A qh qs` and `qs ≤ 2^64`. The
probability is over a uniform 32-byte seed and the lazily sampled oracle, in
the per-key game with the model's own `generateKeypair`, `sign` and `verify`.

What this covers and does not:

* *ChaCha20 as an oracle: two separate claims.*
  1. *Within the formal model* (proved): the seed hop charges every
     adversarial query on the secret seed (`qh/2^256`), and
     `expand_slices_sum` gives the three coins their independent uniform
     distribution.
  2. *Against actual ChaCha20* (not proved, not implied): the model's oracle
     answers each `(seed, length)` request independently, while ChaCha20's
     stream is prefix-consistent. That difference can be detected with any
     *known* seed, with no guess of the secret one. So the `qh/2^256` term
     does not justify replacing actual ChaCha20 with this oracle.
  Replacing the implemented expansion by the model's is a separate
  computational assumption about ChaCha20 (for example, that its output on a
  uniform secret key, independent of every other request, is indistinguishable
  from uniform `3n` bytes). Any implementation-level security claim must
  state and keep it.
* *Independent domains.* BLAKE3's compression is built from the ChaCha
  quarter-round. The model treats mode 3 and BLAKE3's modes 0–2 as
  independent domains of one oracle, and that stays an assumption.
* *Tape range.* An answer of `L` bytes is uniform only when `256^L` divides
  `R`. The theorem holds for every `c > 0`, so `c` can be chosen to cover the
  adversary's longest request.
* *The seed itself.* The per-step seed must be uniform. DSM derives it as
  keyed-BLAKE3(S_master, "DSM/ek/v1\0" ‖ …) (`derive_ephemeral_seed`). That
  derivation is a separate DSM-layer hop and is not covered here.
* *Per key.* The bound is per key (C66 below composes many keys).
* *128f.* SPHINCS+-128f's real-game composition (C61 plus `seed_hop`) is not
  stated. DSM's ephemeral keys use SPHINCS+-256f.

**Many keys: reordering the target's key generation** (`RomMulti.lean`,
`RomQCost.lean`, `RomMultiKey.lean`, claim trace C66).

C57–C65 assume the target key's generation is the first oracle activity. In
a multi-key game it comes after other keys, signatures and hash queries, at
a point the adversary chooses. C57–C65 are unchanged; the step is a
game-level transformation in front of them.

*The multi-key game* (`mplay`). The adversary (`MAdv`) makes hash queries,
creates keys (`newKey`, answered with the new public key), asks for
signatures under any created key, and finally claims a forgery `(j, m, s)`.
Key `j` is generated by the model's `generateKeypair` from seed `sd j`, when
the adversary asks for it. Signing and verification are the model's own,
with the single-key game's legality check. The claim wins if `m` is legal, was
not signed under key `j`, and verifies under key `j`'s public key. `MBudget M
qh qk qs`: at most `qh` hash queries, `qk` keys and `qs` signing queries
(over all keys) on every path.

*1. Split at the target's creation* (`mplay_split`). For a target index `i`
and target seed `s`:

    mplay (sd with s at i) = X >>= fun x => if created x then Ygen s >>= Z x else Z' x

`X = mUntil` runs the game until the adversary asks for key `i`. *When* it
asks is chosen by the adversary from everything it has seen; `created x`
records whether it did. `X` reads only the seeds of keys below `i`, so the
target's seed `s` enters only through `Ygen s`. This is where independence
is stated: the sum over `s` in the theorems below is over the target's seed
alone, for every choice of the other seeds. A forgery against key `i` implies
the target was created (`leaves_mUntil`).

*2. Reordering* (`reorder`). Generic in the result type:

    G  = X >>= fun x => if c x then Y >>= Z x else Z' x
    G' = Y >>= fun y => X >>= fun x => if c x then Z x y else Z' x

In `G'` the target is generated first, but its key is passed to the
continuation only at the original creation point. On a tape `t`, let `a` be
the fresh draws of `X` alone and `b` those of `Y` alone on the rest of the
tape. The coupling `phiT` moves the `b`-block in front of the `a`-block. It is
a bijection on tapes of length `N ≥ A + B` (`psi_phi`, `phi_psi`, `tsum_bij`),
where `A` and `B` bound `a` and `b`. Pointwise (`reorder_point`), if the
target is created and `X` alone and `Y` alone draw no common request (`Ov`),
`G` on `t` and `G'` on `phiT t` give the same result. This holds for any
result type, so a game returning the adversary's full view would be covered
too. Memoized requests, which consume no tape coordinate, are what `Ov` rules
out: every other request is drawn fresh in both orders, from the same tape
coordinate (`run_shift`, `run_equiv`). So:

    Pr[target created ∧ P(G)] ≤ Pr[P(G')] + Pr[Ov]

*3. The overlap event, by provenance* (`gk_shape`, `ov_incl`). Every request
the target's key generation draws, run alone from a fresh table, is one of:

* the expansion request `⟨3, ChaCha20Rng, [], s, 3n⟩`;
* the two key derivations, whose inputs are PK.seed and SK.seed of the
  expansion output on the fresh coordinate `p` (where `p = a`, the first
  coordinate after `X`'s draws);
* a request keyed by the tweak key or by the PRF key, the outputs on the
  fresh coordinates `p+1` and `p+2`.

The last group is all of the XMSS tree (`k_xmssNode`). So `Ov` implies one of
`X`'s requests (a function of the tape below `p` and of the earlier seeds)
equals one of five values, each never read by `X`: the seed `s`, PK.seed,
SK.seed, the tweak key, or the PRF key. Each is a uniform 256-bit value (for
SPX256f) given everything before it, which is the conditional unpredictability
the overlap needs. None of the overlap cases is a collision between two
key-derived values or a structural collision; they are all guesses.

*4. Its probability* (`ov_count`). Per request of `X`:

* the seed is named at most once (`seed_sum`, via `guess_bound`);
* each of the four tape values is hit with probability `1/256^n` or
  `1/256^32` (`hitsB_sum`: a fixed-coordinate hit for a general hit
  function, with the slice counts `cnt_pk`, `cnt_sk`, `cnt_key`).

Over tapes and the target's seed:

    Pr[Ov] ≤ A·(3/256^n + 2/256^32),  = 5A/2^256 for SPX256f

Here `A` bounds `X`'s draws. The coefficient is 5 per earlier request. It is
not 17,185 (the target's key-generation request count): a key-generation
request can match an earlier one only through one of the five values.

*5. The reduction* (`simB`, `sim_before`, `sim_after`, `sim_target`). The
reordered game is, request for request, the single-key real game of C65
against an adversary `redB` that does not depend on the target's seed. It:

* simulates every other key's key generation and signing, and the
  verification of a claim against another key, with its own hash queries
  (`qtA`);
* takes the challenger's public key as key `i` at the original creation
  point;
* forwards key `i`'s signing queries and a claim against key `i`.

The two query trees ask the same requests in lockstep (`TagRel`; the
challenger/adversary tags differ). Runs then agree on every tape
(`run_tagRel`), and a forgery against key `i` is a win of `redB`.

*6. Explicit simulation costs* (`RomQCost.lean`, `budget_simB`). Request
counts of the model's routines as query trees:

* key generation `kgC + 1` (17,186 at SPX256f, `a_keygen`);
* signing `signC` (1,704,961, `a_sign`);
* verification `verC` (17,523, `a_verify`).

The reduction's budget is `Budget (redB pk) Q qs` with

    Q = mQ = qh + qk·(kgC + 1) + qs·signC + verC
      = qh + 17186·qk + 1704961·qs + 17523  (SPX256f)

The same `Q` bounds the multi-key game's requests (`cnt_mUntil`), so `A = Q`.

*7. One target* (`forge_target_256f`). For every target index `i` and every
choice of the other keys' seeds, averaged over the target's uniform seed and
the oracle:

    Pr[forge under key i] ≤ (22·Q + 368023)/2^256 + 5·Q/2^256

The first term is C65 (`real_win_256f`) at the reduction's budget; the
second is the overlap. Tapes have `N = Q + 1704962·qs + 398863` coordinates,
more than either game draws.

*8. All keys* (`forge_any_256f`). Seeds are an independent uniform 32-byte
vector, one per key. An accepted claim names one of the at most `qk` keys
(`leaves_mplay`), so a union over targets, with `coord_avg` averaging out one
seed coordinate at a time, gives:

    Pr[forge under some key] ≤ qk·(27·Q + 368023)/2^256

Evaluated outside Lean:

| `qh` | `qk` | `qs` (all keys) | bound |
|---|---|---|---|
| 2^64 | 2^20 | 2^64 | about 2^-146.5 |
| 2^64 | 2^32 | 2^64 | about 2^-134.5 |
| 2^64 | 2^20 | 2^40 | about 2^-167.1 |

What this covers and does not:

* *Independent uniform seeds.* The keys' seeds are sampled independently and
  uniformly (the independent-seed hybrid). DSM derives per-step seeds from
  S_master with keyed BLAKE3. That hop, and the final DSM statement, are not
  covered.
* *The ChaCha20 boundary of C65 still applies*, unchanged: the expansion is
  a random-oracle request, and against actual ChaCha20 that is a separate
  computational assumption.
* *Loss.* The union over targets costs a factor `qk`. The reduction's budget
  charges every other key's key generation and every signature (under any
  key) as hash queries, which is where `17186·qk + 1704961·qs` comes from.
  `A = Q` uses the whole game's request bound as the bound on requests
  before the target's creation.
* *SPX256f only* for the composed numbers; `reorder`, `ov_count` and the
  reduction are stated for every variant.

**DSM's per-step seed derivation and the PRF hop** (`RomDerive.lean`, claim
trace C67).

DSM derives each per-step key's seed as (`derive_ephemeral_seed`, model
`ekSeedInput`):

    E = keyed-BLAKE3(Smaster, "DSM/ek/v1" ‖ 0x00 ‖ alg_id ‖ chain_id ‖ h_n ‖ C_pre ‖ k_step)

The production callers (`derive_per_step_ek`, the step fixture) all pass
`ALG_ID_SPX256F`. CrossCheck replays this encoding against the Rust vectors
(not run here).

*Context injectivity* (`ekSeedInput_inj`). Distinct
`(alg_id, chain_id, h_n, C_pre, k_step)` give distinct inputs, for *any*
algorithm identifiers, including ones of different lengths. The four context
fields are 32 bytes each, so the total length fixes `|alg_id|`; the fields
then follow by fixed-width binding. This generalizes the existing
fixed-width `ek_seed_preimage_binding`.

*Domain separation* (`ekDom_coins`). Smaster also keys the ML-KEM coins
derivation, `"DSM/kyber-coins/v1" ‖ 0x00 ‖ …`. Its first ten bytes differ
from `"DSM/ek/v1" ‖ 0x00`, so no coins input is a per-step input.

*Repeated contexts.* The game identifies keys by context. Asking again for a
context returns the existing key and creates no new one. In the code this is
recomputation: the seed is a function of `(Smaster, context)`, and key
generation is deterministic. Distinct contexts are distinct inputs of the
derivation function (by injectivity), and the proof uses exactly this
(`dsim`).

*The DSM game* (`dplay`, `DAdv`, `DBudget A qh qn ql qs`):

* the adversary gets `aux K`, a function of Smaster, at the start (see the
  ML-KEM point below);
* it asks for the per-step key of any context it chooses, adaptively, from
  everything it has seen (`newKey`, at most `qn` requests, repeats included);
* it asks for any other Smaster-keyed derivation outside the per-step domain
  and gets the full output (`leak`, at most `ql`). This covers the ML-KEM
  coins, which the encapsulation's recipient recovers;
* it makes hash queries (`qh`) and signing queries under any per-step key
  (`qs`), and claims a forgery.

The derivation is a request to a function: `FQT` query trees ask the random
oracle and the derivation function.

* *Real world* (`resF (dsmF K)`): keyed BLAKE3 under `K = Smaster`, the
  model's `Blake3.keyedHash`. Its output has 32 bytes and is the key
  generation seed unchanged (`dsmF_length`, `seedOf_dsmF`).
* *Ideal world* (`resL`): a lazily sampled random function. It is one
  function, sampled from one vector of `qn + ql` uniform 32-byte values,
  answering every input, per-step or not.

*Steps:*

1. `split_rf`: a lazily sampled random function on two disjoint domains is
   two independent lazily sampled random functions. This is exact on every
   oracle tape, by induction over the query tree with a single-table/two-table
   invariant (`TabInv`), so the adaptive choice of inputs is part of the
   statement, not a fixed list of seeds.
2. `dsim`: the ideal DSM game, with the per-step domain answered from vector
   `ss1`, is literally the multi-key game of C66 with seeds `ss1` in creation
   order, against the adversary `trans`. `trans` asks for a new key only for
   a new context and answers the other derivations from its own random
   function. Its budget is `MBudget qh qn qs` (`mbudget_trans`). The
   derivation requests are counted by `fc_dplay`.
3. `dsm_ideal_256f`, from C66's `forge_any_256f` for every leak vector and
   every Smaster:

       Pr_ideal[forge under some per-step key] ≤ qn·(27·Q + 368023)/2^256

   with `Q = qh + 17186·qn + 1704961·qs + 17523`.
4. `dsm_forge_256f`: the real game, as a distinguisher with at most `qn + ql`
   derivation queries that is given `aux K`, satisfies

       Pr_real[DSM forgery] ≤ Adv + qn·(27·Q + 368023)/2^256

   where `Adv = Pr_real − Pr_ideal` is that distinguisher's PRF advantage.

That is the target composition, with `B` constructed: `B` is the DSM game
itself, simulating the SPHINCS+ random oracle with its own coins. `Adv` is
defined, not bounded: it is the computational assumption.

What this covers and does not:

* *The PRF assumption is stated with auxiliary input.* DSM also derives the
  published ML-KEM key from Smaster through an *unkeyed* BLAKE3 hash,
  `generate_kyber_keypair_from_entropy(Smaster, "DSM/kyber\0")` (in
  `genesis.rs` and `b0x_sdk.rs`). So the assumption needed is that keyed
  BLAKE3 under Smaster is a PRF *even given* that public key (`aux`). This is
  not the standard PRF assumption. Deriving the ML-KEM entropy as another
  keyed-BLAKE3 output under Smaster would put every use of Smaster behind the
  one PRF and remove the auxiliary input.
* *Smaster itself.* `K` is uniform and independent of everything except
  `aux K`. DSM derives Smaster as `kdf32(s0, "DSM/Smaster/v2", G ‖ DevID ‖
  aph)`, with `s0 = kdf32(wallet_seed, "DSM/s0/v2", …)`. The device's AK is
  not derived from `s0`: it comes from a sibling,
  `kdf32(kdf32(wallet_seed, "DSM/device-seed/v2", …), "DSM/device-ak/v2", …)`.
  Public values derived from `wallet_seed` (genesis nonce, AttA, the AK and
  GRK public keys, DevID) sit beside Smaster in the tree. That derivation is a
  separate hop and is not covered.
* *Two idealizations side by side.* In the real world the derivation is
  concrete keyed BLAKE3, while SPHINCS+'s hashing is the random oracle of
  C54–C66. As before, the model treats them as unrelated functions,
  although they share BLAKE3.
* *The ChaCha20 boundary of C65 still applies.*
* *The number.* At `qh = qs = 2^64` and `qn = 2^20`, the second term is
  about 2^-146.5 (C66).

Still open, and needed before this is a number for DSM:

* the derivation of Smaster from `s0`, and a PRF assumption for keyed
  BLAKE3 under Smaster that allows the ML-KEM public key as auxiliary input
  (C67). The multi-key accounting is C66, and the per-step derivation hop to
  `Pr ≤ Adv + qn·(27Q + 368023)/2^256` is C67.

**Key schedule KS1** (`KeySchedule.lean`, claim trace C68).

The schedule C67 describes above, in which every node is
`kdf32(secret, tag, …)` (HKDF with the domain tag as the Extract salt), is
the schedule C67 was stated against, and that description stays as its
historical boundary. DSM now derives its identity secrets with KS1
(`core::identity::key_schedule`, genesis profile `MnemonicV3-KS1`, client
schema 30, no migration): one Extract per secret root under a fixed protocol
salt, and domain separation only in the Expand `info`. HMAC is HMAC-BLAKE3
(RFC 2104, 64-byte block), Extract and Expand are RFC 5869.

    mnemonic (24 words) -> wallet_seed = BIP39 seed (empty passphrase)
    PRK_w  = Extract("DSM/kdf/wallet-root/v1" 0x00, wallet_seed)
      genesis nonce  = Expand(PRK_w, "DSM/genesis-public-nonce/v3"   0x00 lp(net) idx)   public
      GRK seed       = Expand(PRK_w, "DSM/genesis-root-authority/v2" 0x00 lp(net) idx ver)
      AttA           = Expand(PRK_w, "DSM/atta/v3"                   0x00 G slot)        public
      device seed    = Expand(PRK_w, "DSM/device-seed/v3"            0x00 G slot)
      s0             = Expand(PRK_w, "DSM/s0/v3"                     0x00 G slot aph)
      SDK entropy    = Expand(PRK_w, "DSM/sdk-entropy/v3"            0x00 DevID G)
      recovery AEAD  = Expand(PRK_w, "DSM/recovery-aead/v2"          0x00)
      recovery auth. = Expand(PRK_w, "DSM/recovery-authority/v2"     0x00)
    PRK_d  = Extract("DSM/kdf/device-root/v1" 0x00, device seed)
      AK seed        = Expand(PRK_d, "DSM/device-ak/v3" 0x00 aph)
    PRK_s0 = Extract("DSM/kdf/s0-root/v1" 0x00, s0)
      Smaster        = Expand(PRK_s0, "DSM/Smaster/v3"            0x00 G DevID aph)
      at-rest key    = Expand(PRK_s0, "DSM/chain-head-at-rest/v3" 0x00 G DevID)
    keyed-BLAKE3 under Smaster:
      per-step seed  "DSM/ek/v1" 0x00 …           (C67)
      ML-KEM coins   "DSM/kyber-coins/v1" 0x00 …  (C67)
      ML-KEM seed    "DSM/ml-kem-identity/v1" 0x00 "ML-KEM-768"

`lp(x)` is `|x|` as u32 little-endian followed by `x`; `idx`, `ver` and
`slot` are u32 little-endian; `G`, `DevID` and `aph` are 32 bytes. Compared
with the earlier schedule: sibling outputs are Expands of one PRK rather
than HMACs of one secret under different public salts; the at-rest key no
longer uses `s0` directly as a keyed-BLAKE3 key; the published ML-KEM key no
longer comes from an unkeyed hash of Smaster; the recovery keys no longer go
through Argon2id of the phrase text but through `PRK_w`.

*Kernel-checked (C68):*

* `ks_salts_nodup`: the three Extract salts are distinct.
  `ksLabels_nul_free`, `ksLabels_nodup`: the eleven Expand labels contain no
  0x00 and are distinct, so `label ‖ 0x00` determines the label
  (`ksInfo_split`).
* `wnode_info_inj`: under `PRK_w`, the `info` string determines the node and
  its whole context, for u32 integers and network ids shorter than 2^32
  bytes (as the Rust types guarantee). Distinct (node, context) pairs are
  HMAC queries at distinct inputs; the same pair is recomputation, not a new
  output.
* `snode_info_inj`: under `PRK_s0`, Smaster and the at-rest key are Expands
  at distinct inputs for every context. `akInfo_inj`: the AK seed's input
  determines `aph`.
* `smaster_inputs_distinct`, `ekDom_mlkem`: the three keyed-BLAKE3 inputs
  under Smaster are pairwise distinct, and the ML-KEM identity input is
  outside the per-step domain.
* `dsm_forge_256f_ks1`: C67's `dsm_forge_256f` with no auxiliary input
  (`aux := []`). Under KS1 the ML-KEM identity seed is one more keyed-BLAKE3
  output under Smaster, at an input outside the per-step domain, so in
  C67's game it is one of the `ql` revealed derivations and the adversary
  computes the public key itself. `Adv` is then the ordinary PRF advantage
  of keyed BLAKE3 under Smaster with at most `qn + ql` queries. This is an
  instance of C67; C67 itself is unchanged.

*Implementation checks (tests, not proofs):*

* `key_schedule::tests::ks1_test_vectors` fixes twelve outputs, one per
  node. An independent implementation written from the description above
  (`scripts/ks1_reference.py`, HMAC and HKDF over the `blake3` Python
  package) prints the same twelve values byte for byte.
* *Mnemonic.* Every path from a phrase to a wallet seed
  (`parse_wallet_mnemonic`) refuses any phrase that is not a valid 24-word
  English BIP39 phrase; a 12-word phrase is refused, not reinterpreted.
  Length says nothing about entropy, so wallet creation
  (`system.createGenesisV2`) also requires the phrase
  `system.generateMnemonic` produced in the same process, which is 32 bytes
  from the OS CSPRNG encoded as 24 words. Restore accepts any valid 24-word
  phrase: its entropy was fixed when the wallet was created. That the OS
  CSPRNG gives 256 bits of min-entropy is an assumption about the platform.
* *The at-rest key.* `s0` has exactly two uses in the code, as the Extract
  input of `PRK_s0` for Smaster and for the at-rest key. If `PRK_s0` is
  uniform and HMAC-BLAKE3 keyed by it is a PRF, the at-rest key (an output
  at one input, `snode_info_inj`) gives no advantage beyond the PRF
  advantage in computing Smaster (an output at another input). Recovering
  `s0` or `PRK_s0` would compute Smaster, so neither is exposed either,
  under the same assumption. This argument is the standard PRF step and is
  not machine-checked here; it is part of the hybrids below.

Not covered by C68 (C69 below composes the hop from KS1 to C67's uniform `K`):

* *Extract.* That `PRK_w` is close to uniform when `wallet_seed` is the
  BIP39 seed (PBKDF2-HMAC-SHA512) of a 256-bit mnemonic. This is an
  assumption on HMAC-BLAKE3 as an extractor (or a random oracle) and is not
  proved; the final bound must carry the mnemonic's entropy.
* *Expand hybrids.* HMAC-BLAKE3 as a PRF under `PRK_w`, `PRK_d` and
  `PRK_s0`, with the public siblings disclosed (the genesis nonce, AttA, and
  the AK, GRK and recovery-authority public keys, which are functions of
  sibling outputs), and the Extracts of `PRK_d` and `PRK_s0` from uniform
  outputs. Then Smaster is uniform up to those advantages, which is C67's
  `K`.
* *Two idealizations side by side*, as in C67: HMAC-BLAKE3 and keyed BLAKE3
  are concrete functions next to the random oracle for SPHINCS+ hashing,
  although all share BLAKE3. The ChaCha20 boundary of C65 still applies.
* *Compatibility.* The same phrase derives a different identity under KS1
  than under the earlier schedule, and 12-word wallets cannot be restored.
  Identities from the earlier schedule are outside this claim.

**From KS1 to C67** (`KeyScheduleHop.lean`, `KeyScheduleChecks.lean`, claim
trace C69).

The model defines HMAC-BLAKE3 and HKDF as DSM computes them (`hmacB3`,
`hkdfExtract`, `expand32`). `KeyScheduleChecks.lean` runs these
definitions on the inputs of `key_schedule::tests::ks1_test_vectors` and
gets the same twelve values as the Rust code. That is an executed check,
not a proof.

*The game* (`fromWallet`, H0). The entropy `e` is uniform in `[0, 2^256)`,
and the wallet seed is `bip e` for an arbitrary function `bip` (BIP39's
PBKDF2 is not modeled). Smaster is derived by KS1, and C67's DSM game is
played under it. The adversary is also given `pubOf` of the seven siblings
of `s0` under `PRK_w` (the genesis nonce, GRK seed, AttA, device seed, SDK
entropy and both recovery keys, all in full) and of the at-rest key, for an
arbitrary `pubOf`. `G` and `DevID` are arbitrary functions of earlier
outputs (`WCtx`).

*Hybrids.* Each is the real or ideal world of a named distinguisher:

* H1: `PRK_w` uniform. The distinguisher is `fromW`, the game given
  `PRK_w`.
* H2: Expand under `PRK_w` is a lazily sampled random function. The
  distinguisher is `distW`, which makes eight requests.
* H3: `PRK_s0` uniform. The distinguisher is `fromS0`, the game given
  `PRK_s0` and the siblings.
* H4: Expand under `PRK_s0` is a random function. The distinguisher is
  `distS`, which makes two requests.

*Kernel-checked:*

* `resL_kprog`: against a lazily sampled random function, every request of
  a straight-line derivation with distinct KS1 labels is fresh, however its
  fields depend on earlier outputs. Its outputs are therefore the next
  entries of the uniform vector.
* `idealW_eq`: the ideal world of `distW` is the real world of the Extract
  of `s0`. The siblings and `s0` are independent uniform values, and `s0`
  is used only as the input of that Extract.
* `idealS_eq`: the ideal world of `distS` makes Smaster and the at-rest key
  independent uniform values. Then H4 is C67's real game with a uniform
  Smaster that is independent of everything the adversary is given, and
  there is no auxiliary input.
* `ks1_forge_256f`:

      Pr[H0] ≤ ΔExt_w + ΔPRF_w + ΔExt_s0 + ΔPRF_s0 + E[Adv_C67]
               + qn·(27·Q + 368023)/2^256

  with `Q = qh + 17186·qn + 1704961·qs + 17523`. The terms are:
  * `ΔExt_w`: the advantage of `fromW` between `Extract(saltW, bip e)` and
    a uniform PRK.
  * `ΔPRF_w`: the advantage of `distW` between Expand under a uniform PRK
    and a random function.
  * `ΔExt_s0`: the advantage of `fromS0` between `Extract(saltS0, u)` for a
    uniform `u` and a uniform PRK, averaged over the siblings.
  * `ΔPRF_s0`: the advantage of `distS`, as for `ΔPRF_w`.
  * `E[Adv_C67]`: C67's PRF advantage of keyed BLAKE3 under a uniform
    Smaster, with no auxiliary input, averaged over the disclosed values.

  The bound is stated in counts over Nat, as in C67.

What this covers and does not:

* *Every advantage is defined, not bounded.* `ΔExt_w` is where the
  mnemonic's entropy enters. It compares the Extract of the BIP39 seed of a
  uniform 256-bit entropy with a uniform key. For a mnemonic with less
  entropy, or a BIP39 seed far from uniform, this term is large and the
  bound says nothing.
* *`ΔExt_s0` needs more than a PRF keyed by its key input.* HMAC-BLAKE3 is
  keyed by the public salt, and the secret `s0` is its message. Small
  `ΔExt_s0` is an extractor (or dual-PRF) property, assumed here and not
  implied by the Expand assumptions.
* *The at-rest key is disclosed in the bound.* The adversary is given it,
  and the bound still holds. So, under these assumptions, leaking the
  at-rest key does not help to forge, and neither `s0` nor Smaster can be
  computed from it. Knowing either would let the adversary compute Smaster,
  and in H4 Smaster is uniform and independent of the at-rest key.
* *The device branch is not hybridized.* The device seed is disclosed in
  full, so the AK and DevID, computed from it, need no assumption about
  `PRK_d`.
* *Two idealizations side by side*, as in C67. HMAC-BLAKE3 and keyed BLAKE3
  are concrete functions, next to the random oracle for SPHINCS+ hashing,
  although all of them share BLAKE3. The ChaCha20 boundary of C65 still
  applies.
* *The number.* At `qh = qs = 2^64` and `qn = 2^20`, the last term is about
  2^-146.5, as in C66 and C67.

**C69's assumptions, named** (`KeyScheduleNamed.lean`, claim trace C70).

`ks1_forge_256f_named` restates C69 with each of its five advantages as a
hypothesis with an explicit bound:

* (A1) Extract of the wallet seed: `ΔExt_w ≤ ε₁/2^256`;
* (A2) Expand under `PRK_w`: `ΔPRF_w ≤ ε₂/2^256`;
* (A3) Extract of `s0`: `ΔExt_s0 ≤ ε₃/2^256`;
* (A4) Expand under `PRK_s0`: `ΔPRF_s0 ≤ ε₄/2^256`;
* (A5) C67's keyed-BLAKE3 PRF under Smaster, for every disclosed value:
  `Adv_C67 ≤ ε₅/2^256`.

The conclusion is one number:

    Pr[forgery] ≤ (ε₁ + ε₂ + ε₃ + ε₄ + ε₅ + qn·(27·Q + 368023))/2^256

Each advantage is in counts at its own scale, exactly as C69 defines it.
This adds no proof content to C69; it states plainly what C69 assumes.

**The key derivation in the random-oracle model** (`RomKdf.lean`, claim
trace C71).

The model treats HMAC-BLAKE3 and keyed BLAKE3 as one random oracle, the KDF
oracle. Its inputs are domain-separated: `hmIn k m` for HMAC under key `k`,
and `kbIn k x` for keyed BLAKE3 under key `k`. The KDF oracle is independent
of the random oracle for SPHINCS+ hashing. Under this model all five
assumptions of C70 are proved, not assumed.

*The game* (`romGame`):

* The entropy `e` is uniform in `[0, 2^256)`, and the wallet seed is
  `bip e`. BIP39 is not modeled: `bip` is any function, and `β` bounds how
  many entropies share one seed (`β = 1` if `bip` is injective).
* KS1 runs as twelve requests to the KDF oracle (`ks1Rom`): the Extract of
  the wallet seed, eight Expands under `PRK_w`, the Extract of `s0`, and
  Smaster and the at-rest key under `PRK_s0`.
* C67's DSM game (`dplay`, unchanged) is then played under the derived
  Smaster. The adversary is given any function of the seven siblings, in
  full, and of the at-rest key.
* Each derivation request `x` of that game is the KDF-oracle request
  `kbIn Smaster x`: per-step seeds, ML-KEM coins and the ML-KEM identity
  seed.
* A request `0xff ‖ z` is instead the adversary's own query of the KDF
  oracle at `z`. So the adversary computes HMAC-BLAKE3 and keyed BLAKE3 at
  any input it likes, through C67's `leak`, interleaved with the rest of the
  game. These queries count in `ql`. DSM's own derivation inputs begin with
  `DSM/`, so none of them is read as a query.

*Kernel-checked:*

* `resL_ks1Rom`: the twelve challenger requests are always fresh, whatever
  values came before. Their classes (the HMAC key length, and for a 32-byte
  key the Expand label) are distinct. So they take the first twelve uniform
  values, and the table then holds only those twelve requests.
* `couple`: identical until bad. The game agrees with C67's ideal game,
  where every derivation request is answered by one lazily sampled
  function, unless one of the game's requests, mapped to the KDF oracle,
  lands on a challenger request or coincides with another.
* `bad_hits`: that happens only if one of the adversary's own queries:
  * is the Extract input of the wallet seed or of `s0`; or
  * is keyed by `PRK_w`, `PRK_s0` or Smaster.
* `e_family`, `coord_family`, `href_bound`: C67's ideal game reads none of
  those five values. Each query therefore hits the wallet-seed input with
  probability at most `β/2^256`, and each of the other four with
  probability at most `1/2^256`. C67's `dsm_ideal_256f` bounds the ideal
  game.
* `rom_forge_256f`:

      Pr[forge under some per-step key] ≤ (qn·(27·Q + 368023) + (qn + ql)·(β + 4)) / 2^256

  with `Q = qh + 17186·qn + 1704961·qs + 17523`.

What this covers and does not:

* *No computational assumption on the key derivation is left*: the four KS1
  steps and C67's keyed BLAKE3 are all covered. What remains is the model.
  * HMAC-BLAKE3 is a random oracle. This is a modeling choice; it is not
    derived from BLAKE3 being one.
  * Keyed BLAKE3 is the same oracle, separated by the input tag.
  * Both are independent of the SPHINCS+ oracle, as in C67, although all
    of them share BLAKE3.
* *The mnemonic.* The bound holds for a uniform 256-bit entropy, and β
  enters only through the wallet-seed term. A generated DSM mnemonic carries
  32 bytes from the OS random generator; that this is uniform is an
  assumption about the platform.
* *Disclosure.* The adversary sees all seven siblings in full and the
  at-rest key, and still learns nothing about Smaster beyond the bound.
* *The ChaCha20 boundary of C65 still applies* inside SPHINCS+.
* *The number.* At `qh = qs = 2^64`, `qn = 2^20`, `ql = 2^64` and `β = 1`,
  the second term is about `5·2^64/2^256 = 2^-189.7`. The first is C66's,
  about 2^-146.5.

## Assumptions, stated plainly

* Every BLAKE3 role, and ChaCha20 seed expansion, is an independent random
  oracle (one oracle, distinct requests). For ChaCha20 this is not a
  faithful model of the stream (prefix consistency is visible with any known
  seed). The implementation-level claim needs a separate assumption that
  the expansion of a uniform secret seed is indistinguishable from uniform
  bytes (see C65). Keyed BLAKE3 under different keys,
  `derive_key` under different contexts and the XOF are treated as unrelated
  functions even though they share BLAKE3's compression function.
* At most 2^64 signatures per key (the ITSR bound is monotone in q_s; the
  check is at 2^64). Multi-key (one ephemeral key per step): for independent
  uniform seeds, `qk` keys cost a factor `qk` and the reduction's budget
  grows with every simulated key generation and signature (C66).
* Per-step seeds (C67): keyed BLAKE3 under Smaster is a PRF even given the
  ML-KEM public key DSM derives from Smaster by an unkeyed hash, and Smaster
  is uniform apart from that. Not proved; the bound carries its advantage.
* Key schedule KS1 (C68): the injectivity and domain separation of every
  derivation input are proved. That `PRK_w` is close to uniform for a
  256-bit mnemonic, and that HMAC-BLAKE3 Expand is a PRF under each PRK, are
  assumptions, composed into the bound in C69; under KS1 the PRF assumption
  of C67 needs no auxiliary input.
* From KS1 to C67 (C69): the Extract of the BIP39 seed of a uniform 256-bit
  entropy, Expand under a uniform `PRK_w`, the Extract of a uniform `s0`
  under a public salt, and Expand under a uniform `PRK_s0` are each close
  to uniform or random for the named distinguishers; not proved, and the
  bound carries each advantage.
* In the random-oracle model for the key derivation (C71), HMAC-BLAKE3 and
  keyed BLAKE3 are one random oracle with domain-separated inputs,
  independent of the SPHINCS+ oracle. Under it, C69's five assumptions are
  proved. Without that model, C70 states them as named hypotheses.
* Adversary cost is counted in oracle queries only; local computation is free.
* Classical adversaries only. The quantum picture is in
  `SPHINCS_QROM_NARRATIVE.md` and is not machine-checked.
