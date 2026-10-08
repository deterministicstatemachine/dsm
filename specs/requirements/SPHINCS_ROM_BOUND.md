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
  child of its address (`kids`), to any depth.
* A revealed handle is never protected, i.e. never an entry that mentions
  SK.seed or SK.prf.

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
  target. 256f needs a wide-class count of the same kind.

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

Still open, and needed before this is a number:

* the step bound `S` and the adversary-step bound `AA` for H1', derived from
  the query budget;
* a wide-class count for SPHINCS+-256f;
* the canonical-collision bound on H1''s table;
* deriving the budget hypotheses from the adversary's query budget;
* the seed hop;
* the final composition.

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
