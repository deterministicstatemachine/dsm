# DSM modular (computational) SPHINCS+ proof: interface map

Status: Milestone 1 of the modular-proof plan, audit-prep, 2026-10-08. This
document maps the published, EasyCrypt-verified SPHINCS+ reduction onto DSM's
actual construction and existing Lean evidence, lists every interface
mismatch, specifies the first modular theorem, and orders the proof
obligations. **No new theorem is claimed here.** C57–C71, the Rust code and
every existing security statement are unchanged.

The goal is a second machine-checked security result, beside C71:

| | C71 (existing) | Modular proof (this plan) |
| --- | --- | --- |
| Model | random oracle for every BLAKE3 role | none: named properties of the actual functions |
| Statement | explicit forgery probability | forgery advantage ≤ sum of primitive advantages of constructed adversaries |
| Hash assumptions | ideal random functions | PRF, PRG, ITSR, SM-DT-TCR(-C), SM-DT-DSPR, SM-DT-PRE(-C), SM-DT-UD(-C) |

## 1. Sources

* Barbosa, Dupressoir, Hülsing, Meijers, Strub, *A Tight Security Proof for
  SPHINCS+, Formally Verified*, ASIACRYPT 2024, LNCS 15487, pp. 35–67
  ([PDF](https://pure.tue.nl/ws/portalfiles/portal/350450713/978-981-96-0894-2_2.pdf),
  [ePrint 2024/910](https://eprint.iacr.org/2024/910)).
* EasyCrypt artifact [MM45/FV-SPHINCSPLUS-EC](https://github.com/MM45/FV-SPHINCSPLUS-EC)
  at `a28e4c53897a4bb57b575a177225862d48f824b7` (2026-03-26), the same commit
  `SPHINCS_EXTERNAL_PROOF_ARTIFACTS.md` records. Read for this map:
  `SPHINCS_PLUS.ec`, `FORS_ES.ec`, `FL_SL_XMSS_MT_ES.ec`, `WOTS_TW_ES.ec`,
  `TweakableHashFunctions.eca`, `KeyedHashFunctions.eca`,
  `OpenPRE_From_TCR_DSPR_THF.eca`. Not replayed locally (no EasyCrypt here).
* DSM at `568f9c94` (audit-prep): `crates/dsm-sphincs/src/lib.rs`, its Lean
  model `lean4/Sphincs/Model.lean`, and the existing evidence below.
* Prior DSM records this map builds on, not replaces:
  `SPHINCS_BLAKE3_ROLE_MAP.md` (roles), `SPHINCS_EXTERNAL_PROOF_ARTIFACTS.md`
  (transfer obligations from the same artifact), `SPHINCS_REFINEMENT.md`.

## 2. The published result, decomposed

Paper statements (abbreviated):

* **Theorem 4 (SPHINCS+).** `Adv^EUF-CMA ≤ Adv^PRF_SKG(B0) + Adv^PRF_MKG(B1) +
  Adv^EUF-CMA_M-FORS$(B2) + Adv^EUF-NAGCMA_FL-SL-XMSSMT$(B3)`.
* **Theorem 1 (M-FORS$).** `Adv^EUF-CMA_M-FORS$ ≤ Adv^ITSR_MCO(B0) +
  Adv^SM-DT-OpenPRE_F(B1) + Adv^SM-DT-TCR-C_TRH(B2) + Adv^SM-DT-TCR-C_TRCO(B3)`,
  with targets `t_f = s·l'·k·t`, `t_trh = s·l'·k·(t−1)`, `t_trco = s·l'`.
* **Theorem 2 (OpenPRE).** `Adv^SM-DT-OpenPRE ≤ Adv^SM-DT-DSPR + 3·Adv^SM-DT-TCR`
  (finite message space).
* **Theorem 3 (hypertree).** For an adversary that never queries the collection
  oracle on the hypertree's addresses, `Adv^EUF-NAGCMA_FL-SL-XMSSMT$ ≤
  Adv^M-EUF-GCMA_WOTS-TW$(B0) + Adv^SM-DT-TCR-C_PKCO(B1) + Adv^SM-DT-TCR-C_TRH(B2)`.
* **WOTS-TW$** (reused from the XMSS development, `WOTS_TW_ES.ec`):
  `Adv^M-EUF-GCMA ≤ (w−2)·Adv^SM-DT-UD-C_F + Adv^SM-DT-TCR-C_F + Adv^SM-DT-PRE-C_F`.

The machine-checked low-level form is `EUFCMA_SPHINCS_PLUS`
(`SPHINCS_PLUS.ec` line 4338). Its twelve terms, each the advantage of a named
reduction module:

| # | Term | Function | Reduction module (EasyCrypt) |
| --- | --- | --- | --- |
| 1 | PRF | SKG | `R_SKGPRF_EUFCMA` |
| 2 | PRF | MKG | `R_MKGPRF_EUFCMA` |
| 3 | ITSR | MCO | `R_ITSR_EUFCMA ∘ R_MFORS…` |
| 4 | SM-DT-DSPR (minus SPprob) | F (FORS leaves) | `R_DSPR_OpenPRE ∘ …` |
| 5 | 3 · SM-DT-TCR | F (FORS leaves) | `R_TCR_OpenPRE ∘ …` |
| 6 | SM-DT-TCR-C | TRH (FORS trees) | `R_TRHSMDTTCRC_EUFCMA ∘ …` |
| 7 | SM-DT-TCR-C | TRCO (FORS roots) | `R_TRCOSMDTTCRC_EUFCMA ∘ …` |
| 8 | (w−2) · SM-DT-UD-C | F (WOTS chains) | `R_SMDTUDC_Game23WOTSTWES ∘ …` |
| 9 | SM-DT-TCR-C | F (WOTS chains) | `R_SMDTTCRC_Game34WOTSTWES ∘ …` |
| 10 | SM-DT-PRE-C | F (WOTS chains) | `R_SMDTPREC_Game4WOTSTWES ∘ …` |
| 11 | SM-DT-TCR-C | PKCO (WOTS public keys) | `R_SMDTTCRCPKCO_EUFNAGCMA ∘ …` |
| 12 | SM-DT-TCR-C | TRH (XMSS trees) | `R_SMDTTCRCTRH_EUFNAGCMA ∘ …` |

Game semantics that matter for DSM (from `TweakableHashFunctions.eca`): in
every SM-DT game the public parameter `pp` is sampled first, but the adversary
commits its targets (`pick`, oracle `f pp tw x`) **before** it receives `pp`
(`find(pp)` / `distinguish(pp)`). Tweaks must be distinct; in the `-C` variants
the collection oracle's tweaks must be disjoint from the targets'. ITSR
(`KeyedHashFunctions.eca`): every query `x` gets a fresh uniform key `k`; the
adversary wins with a new `(k, x)` whose index set `g(f k x)` is covered by the
queried ones.

## 3. Interface correspondence

DSM parameters for the composed result: SPX256f, `n = 32`, `h = 68`, `d = 17`,
`h' = 4` (`l' = 16`), `a = 9` (`t = 512`), `k = 35`, `w = 16`, `len = 67`.
EasyCrypt admits `log2 w ∈ {2, 4, 8}`; DSM's 4 is in range.

| EasyCrypt | Type | DSM function (Rust / Lean) | Match |
| --- | --- | --- | --- |
| `keygen` samples `ms`, `ss`, `ps` independently | — | one 32-byte seed → ChaCha20Rng → `SK.seed ‖ SK.prf ‖ PK.seed` (`generate_keypair_from_seed` / `generateKeypair`, request mode 3) | **No** (I2): needs the PRG hop |
| `skg : sseed → (pseed × adrs) → dgstblock` | PRF | keyed BLAKE3 under `derive_key("DSM/sphincs/v2/prf", SK.seed)` on `PK.seed ‖ ADRS`, first n bytes (`prf`) | shape yes; composite key (I3); PRF address types 5/6 (I4) |
| `mkg : mseed → msg → mkey` | PRF | keyed BLAKE3 under `derive_key("…/prf-msg", SK.prf)` on `PK.seed ‖ M` (signing's `msgKey`, `keyed`) | composite key (I3); `PK.seed` in the input (I3) |
| `mco : mkey → msg → msgFORS × index` | ITSR | `splitDigest(h_msg(R, PK.seed, PK.root, M))`, derive-mode XOF, 49 bytes for 256f (`hmsg`, `splitDigest`) | **No** (I1): DSM binds `PK.seed` and `PK.root` |
| `thfc : int → pseed → adrs → dgst → dgstblock` (collection, by input length) | THF | keyed BLAKE3 under `derive_key("…/thash", PK.seed)` on `ADRS ‖ M`, first n bytes (`thash`), one function for every length | yes (I5): `pp = PK.seed`, `diff = |M|` |
| `f = thfc(8n)` | F | `thash` on n bytes: WOTS chain steps (type 0), FORS leaves (type 3, height 0) | yes |
| `trh = thfc(16n)` | TRH | `thash` on 2n bytes: XMSS nodes (type 2), FORS nodes (type 3, height ≥ 1) | yes |
| `pkco = thfc(8n·len)` | PKCO | `thash` on len·n bytes, type 1 (`wotsCompress`) | yes |
| `trco = thfc(8n·k)` | TRCO | `thash` on k·n bytes, type 4 (FORS roots) | yes |
| chain `ch f ps ad s i x`, hash index `s+i−1` | — | `chain`: `thash` with `hash := start`, `start+1`, … | yes (definitional; EC axioms `ch0`, `chS` hold by `rfl`/induction) |
| `encode_msgWOTS` with axiom `two_encodings` | — | `wotsDigits`: base-16 digits ‖ 3-digit checksum `be 2 (csum·16)` | yes; DSM **proves** the axiom (C22 `WotsChecksum`) |
| `adrs`: 6 abstract int coordinates, `valid_adrsidxs` | tweak | 32 bytes: layer(4) ‖ 0(4) ‖ tree(8) ‖ type(4) ‖ keypair(4) ‖ chain/height(4) ‖ hash/index(4) | needs an explicit map (I6) |
| address types `uniq [ch; pkco; trhx; trhf; trco]` | — | 0, 1, 2, 3, 4 (plus PRF types 5, 6) | yes |
| `idx : [0, l)`, `(tidx, kpidx) = edivz idx l'` | — | `tree = toInt(…) mod 2^(h−h')`, `leaf = toInt(…) mod 2^h'`; `idx = tree·2^h' + leaf` | yes (bijection to prove) |
| signature `(mk, sigFORS, sigHT)` | — | `R ‖ fors ‖ ht`, fixed width (`Params.sigBytes`) | yes |
| messages: any `msg` | — | non-empty, `≤ maxMessageBytes` (`legal`); signer self-check | benign (I10) |

## 4. Security properties: games, DSM instance, Lean status

"Lean definition" means a game in DSM's computational framework
(`SecurityGames.lean`); none of these exists yet except as noted.

| Property | Game (EasyCrypt) | DSM instance | Existing DSM Lean | Theorem still required |
| --- | --- | --- | --- | --- |
| PRG | — (DSM-specific) | ChaCha20Rng: 32 B → 3n B | exact hop `seed_prg_hybrid_bound` (C11), distinguisher explicit | PRG game definition; restate C11 as `Adv^PRG(seedDistinguisher)` |
| PRF (KDF) | `KeyedHashFunctions` PRF | `derive_key(ctx, ·)` on a secret seed | exact hops `prf_key_hybrid_bound`, `msg_key_hybrid_bound` (C15, C16) | PRF game definition; restate hops as advantages |
| PRF (keyed hash) | PRF | keyed BLAKE3 under a uniform 32-byte key | exact hops `prf_function_hybrid_bound`, `msg_function_hybrid_bound` (C15, C16) | as above |
| ITSR | `ITSR`, `O_ITSR_Default` | `h_msg` + `splitDigest`, input `PK.seed ‖ PK.root ‖ M`, key `R` | covered event `forsCoveredEvent` (C31); ROM analysis only (C43, C48–C50) | game definition; reduction `B_itsr` (§6) |
| SM-DT-TCR(-C) | `SM_DT_TCR(_C)` | `thash` with `pp = PK.seed`, tweak = 32-byte ADRS | single event `collisionEvent` (C31) over every role; tweak single use (C19) | game definitions; per-role reductions (#6, #7, #9, #11, #12; #5 via OpenPRE) |
| SM-DT-DSPR | `SM_DT_DSPR`, `SM_DT_SPprob` | F on n-byte inputs (finite) | none | game; Theorem 2 (OpenPRE ≤ DSPR + 3·TCR) for DSM's F |
| SM-DT-OpenPRE | `SM_DT_OpenPRE` | F at FORS leaves | event `forsSecretEvent` (C31) | game; FORS reduction |
| SM-DT-PRE(-C) | `SM_DT_PRE(_C)` | F at WOTS chain positions | event `wotsPreimageEvent` (C31) is **not** a PRE event (I9) | game; WOTS-TW reduction |
| SM-DT-UD(-C) | `SM_DT_UD(_C)` | F on uniform n-byte inputs | none | game; WOTS-TW hybrids, factor (w−2) |
| EUF-CMA (M-FORS$) | `EUF_CMA_MFORSTWESNPRF` | DSM FORS layer, 2^68 instances, with committed context (I1) | extraction `ForsExtraction` (C26) | DSM game; Theorem 1 analogue (§6) |
| EUF-NAGCMA (hypertree) | `EUF_NAGCMA_FLSLXMSSMTTWESNPRF` | DSM hypertree, d = 17, all 2^68 leaves signed once | `HtExtraction`, `XmssExtraction` (C24, C25) | DSM game; Theorem 3 analogue |
| M-EUF-GCMA (WOTS-TW$) | `WOTS_TW_ES.ec` | DSM WOTS, one message per instance | `WotsExtraction` (C23), checksum (C22) | DSM game; WOTS-TW reduction |

## 5. Mismatches and incompatibilities

**I1. `h_msg` binds `PK.root`; EasyCrypt's `mco mk m` does not.** DSM (like
standard SPHINCS+) hashes `R ‖ PK.seed ‖ PK.root ‖ M`. The root depends on every
FORS public key through the hypertree, so the FORS component cannot be
separated from the hypertree with EasyCrypt's game as written. DSM's `PRF_msg`
input is `PK.seed ‖ M` (no root). If the M-FORS game took `(seed, root, M)` as
its message, `mkg` would have to ignore `root`, which breaks the game's
assumption that `mkg` is a PRF on the whole message. **Handling:** a DSM M-FORS
game in which the adversary commits one context `ctx = PK.seed ‖ PK.root` after
receiving the FORS public keys and before any signing query. Signing then uses
`R = MKG(M)` and `mco(R, ctx ‖ M)`. The ITSR game needs no change, since its
input type takes `ctx ‖ M`. *Interface change to the component split;
not blocking.*

**I2. One master seed.** EasyCrypt samples `ms`, `ss`, `ps` independently; DSM
expands one 32-byte seed with ChaCha20. **Handling:** C11's exact hop, restated
as a PRG advantage. After it, `PK.seed` is uniform and independent of the
secret parts, which the SM-DT games need (`pp ← dpp`). *Done structurally; PRG
game to define.*

**I3. Composite PRFs, and `PK.seed` in their inputs.** SKG and MKG are
`derive_key` followed by keyed BLAKE3, so EasyCrypt's one PRF term becomes two
per function (KDF + keyed hash). C15/C16 already prove these four hops exactly.
Both functions also take `PK.seed` as input. In the final hybrid they are
random functions on `PK.seed ‖ ADRS` and `PK.seed ‖ M`. A reduction that must
commit TCR targets before learning `pp = PK.seed` needs the lemma that a random
function on `pp ‖ x`, for fixed `pp`, is a random function on `x`. *Lemma owed;
not blocking.*

**I4. PRF address types.** DSM derives secrets at WOTS_PRF (5) and FORS_PRF (6)
addresses (FIPS 205 style). EasyCrypt calls `skg` at the chain / FORS-leaf
address itself (`skg ss (ps, set_thtbidx ad 0 idx)`). After the PRF hop the
secrets are random-function outputs, so only distinctness of the SKG inputs
matters, and address injectivity gives it (C17, C18). *Benign.*

**I5. The tweakable hash is keyed BLAKE3 under `derive_key(PK.seed)`.** This fits
EasyCrypt's collection: `fc diff pp tw x = thash(pp, tw, x)` for every length,
`get_diff = |x|`, and `in_collection` holds by definition. The hash-function
properties themselves are the assumptions of the modular theorem, as
`SPHINCS_BLAKE3_ROLE_MAP.md` says: the BLAKE3 specification does not state
them for keyed mode under a public key. For SPX256f, n = 32 and there is no
truncation. *Not an incompatibility; it is the assumption.*

**I6. Address encoding.** EasyCrypt uses six abstract coordinates with validity
predicates; DSM uses 32 bytes with a reserved zero word and a 64-bit tree
field. Needed: an explicit injection `adrsEC ↦ ADRS bytes`, and the
correspondence `valid_adrsidxs ↔ InRange`. Most of this exists:
`adrs_bytes_injective` (C17), `AddressRange` (C18) and tweak single use (C19).
*Map to write.*

**I7. Size of the reductions.** The hypertree game signs **all** `l = 2^68`
leaves non-adaptively. The FORS reductions commit targets for every FORS
instance (`t_f = 35·2^77`, `t_trh = 35·511·2^68`, `t_trco = 2^68`), and the
hypertree's are `t_pkco = 16·(2^68−1)/15` and `t_trh = 2^68−1`. The reductions
precompute the whole structure before `pp` is revealed. EasyCrypt does not
bound reduction running time, and neither does DSM's finite framework
(`SeedHybrid.lean` says so). The modular theorem is therefore an
**advantage-only** statement: each assumption must be read as holding for
adversaries of that size. Tightness and runtime are a separate obligation, as
the plan says. *Scope decision, not a blocker.*

**I8. Lean game framework.** DSM's computational layer
(`FiniteExperiment`, deterministic `Strategy`, exact rationals) has no game
type for adversaries that query a stateful challenge oracle in a `pick` phase
and receive `pp` later. Milestone 2 must add one: a query-tree type for the
target and collection oracles (as `QT`/`FQT` do for the ROM), with target and
tweak logs. *Framework work; not blocking.*

**I9. C31's events do not line up one-to-one with EasyCrypt's terms.**
* `collisionEvent` is one event over every role. It must be split by the
  witness address's type and component: F at chains (term 9), F at FORS leaves
  (inside 5), TRH for FORS (6) and XMSS (12), TRCO (7), PKCO (11).
* `wotsPreimageEvent` is a preimage of an **iterated** chain value, which is
  not uniform. Plain PRE does not bound it. EasyCrypt's route is the WOTS-TW
  hybrids: UD with factor (w−2), then TCR and PRE.
* `forsSecretEvent` is EasyCrypt's OpenPRE event: other targets are opened by
  signatures. It reduces through Theorem 2.
* `forsCoveredEvent` is the ITSR event.

C31 is reused as the validity / extraction skeleton, not as the final terms.
*Restructuring required.*

**I10. Message domain and self-check.** DSM rejects empty or over-long messages
and self-checks each signature. This is benign: the games use legal messages
only, and C10 proves that the model signer's signatures verify, under
fixed-width outputs.

**I11. Multi-key and the key hierarchy.** C66, C67, C69 and C71 are stated
over the ROM query-tree game (`QT`, `mplay`, `dplay` with the SPHINCS+ random
oracle). Their game statements cannot enter the computational line. What is
reusable:
* MultiKey (C39): per-key extraction for any joint seed distribution, on the
  `Oracle Id` model;
* C68: KS1 encodings, injectivity and domain separation;
* the generic freshness and arithmetic lemmas of C69 and C71 (`resL_kprog`,
  `hop_chain`);
* the C70 statement shape (named advantages).

Milestone 6 must rebuild the per-step derivation hop (keyed BLAKE3 under
Smaster as a PRF) and the KS1 hops on the computational multi-key game. It
uses a hybrid over adaptively created keys (guess the forged key: factor
`q_k`) in place of C66's lazy-sampling reordering. *As anticipated in the
plan.*

**I12. Plan table correction.** The oracle-independent extraction is
**C17–C30**, not C57–C60. C57–C64 are ROM-game lemmas: H1′ dataflow
(`RomStruct`), pin counts (`RomPhi`, `RomWide`), collision counts (`RomColl`)
and budgets (`RomBudget`). §7 has the full classification.

**I13. Pinned EasyCrypt axioms.** Its development relies on parameter axioms
that DSM must hold as theorems, since DSM admits no axioms:

| EasyCrypt axiom | Meaning | DSM status |
| --- | --- | --- |
| `dist_adrstypes` (three files) | address types distinct | by `decide` on 0–4 |
| `valid_{w,x,f}idxvals_idxvals` | component validity ⇒ global validity | owed with I6 |
| `ch0`, `chS` | chain recursion | `chain` is defined recursively; owed as lemmas |
| `two_encodings` | distinct messages have a strictly smaller digit | **proved** (C22) |
| `in_collection` | each THF is a member of the collection | by definition (I5) |
| ITSR `size_g`, `rng_*`, `eqiks_g`, `neqisvs_g` | shape of the index map | owed for `splitDigest`/`base2b` (structure in `RomDigest`, C49) |

## 6. The first modular theorem: DSM-T1 (M-FORS)

**Statement (target).** For every adversary `A` against the DSM M-FORS game:

    Adv^EUF-CMA_{M-FORS_DSM}(A) ≤ Adv^ITSR_{MCO_DSM}(B0) + Adv^SM-DT-OpenPRE_F(B1)
                                  + Adv^SM-DT-TCR-C_TRH(B2) + Adv^SM-DT-TCR-C_TRCO(B3)

with the composition `Adv^OpenPRE ≤ Adv^DSPR + 3·Adv^TCR` (Theorem 2 for DSM's F)
as a separate theorem.

**The DSM M-FORS game** (`M_FORS_DSM`). Its inputs and outputs:
1. Sample `pp = PK.seed` uniform in n bytes, the FORS secrets as a random
   function on FORS_PRF addresses, and `MKG` as a random function on messages
   (I3).
2. Compute all `2^68` FORS public keys at addresses
   `{layer 0, tree, type 3, keypair = leaf}` with DSM's `thash`.
3. The adversary receives `(pp, all FORS public keys)` and commits
   `ctx` (I1).
4. Signing oracle, at most `q_s` legal fresh messages:
   * `R = MKG(M)` and `(md, tree, leaf) = splitDigest(h_msg(R, ctx ‖ M))`;
   * return `(R, forsSign(md))` at `(tree, leaf)`.
5. The adversary outputs `(M', R', σ')`. It wins if `M'` is fresh and
   `forsPkFromSig(σ', md')` equals the honest FORS public key at
   `(tree', leaf')` from `splitDigest(h_msg(R', ctx ‖ M'))`.

**Reduction adversaries** (each runs `A` and simulates the game exactly unless
its own event occurs):

| Adversary | Game | Phase 1 (before `pp` where applicable) | Output | Budget |
| --- | --- | --- | --- | --- |
| B0 | ITSR on `MCO_DSM(R, ctx ‖ M)` | samples all secrets and `pp` itself, runs `A`; for each fresh signing message queries `O_ITSR(ctx ‖ M)` and uses the returned key as `R` | `(R', ctx ‖ M')` | ≤ q_s queries |
| B1 | SM-DT-OpenPRE on F | targets: every FORS leaf, `F(secret)` at `{tree, leaf, type 3, height 0, index}`; opens exactly the leaves signatures reveal | the forged leaf preimage at an unopened target | t_f = 35·2^77 targets |
| B2 | SM-DT-TCR-C on TRH | targets: every FORS internal node input (left ‖ right) at its address; collection oracle for F (leaves) and TRCO | the colliding node input at the first divergence | t_trh = 35·511·2^68 |
| B3 | SM-DT-TCR-C on TRCO | targets: every FORS root list at type 4 addresses; collection oracle for F and TRH | the colliding root list | t_trco = 2^68 |

Every target set is committed before `pp` is revealed. This is possible
because, after I2 and I3, every honest FORS value depends only on random-function
outputs and on `thash` answers the target oracle supplies. `pp` is used only to
hand `A` its public key in the `find` phase, after all honest values are known.

**Plugging in.** The DSM Theorem-4 analogue (Milestone 5) is:
* C11/C15/C16 restated as PRG / KDF / PRF advantages;
* DSM-T1 for FORS;
* the hypertree theorem (Milestone 4), with the reduction to M-FORS committing
  `ctx` once it has computed the root.

## 7. Reuse of existing DSM results

| Claims | Content | Oracle-independent? | Use |
| --- | --- | --- | --- |
| C10 | the model signer's signatures verify (`signer_correct`, `keygen_sign_verify`); Rust is cross-checked by vectors, not universally refined | yes | game correctness |
| C11, C15, C16 | seed, KDF, PRF hops with explicit distinguishers, exact | yes (`Oracle Id`) | restate as PRG/PRF advantages |
| C17–C19 | address injectivity, range, tweak single use | yes | distinct-tweak conditions of every SM-DT game (I6) |
| C20–C30 | deterministic forgery extraction (paths, chains, WOTS, XMSS, hypertree, FORS, logs) | yes | winning-condition analysis inside each reduction |
| C22 | WOTS checksum | yes | discharges `two_encodings` |
| C31, C32 | final-game event accounting | yes | skeleton; events re-split (I9) |
| C33–C36, C40 | wrapper injectivity / object-level forgery | yes | unchanged on top |
| C39 | multi-key per-key extraction | yes | base of Milestone 6 |
| C41 | query cost | yes | reduction resource accounting |
| C68 | KS1 encodings | yes | Milestone 6 |
| C42–C67, C69–C71 | ROM games, counts, ROM multi-key, ROM KS1 hop | **no** (ROM-specific statements) | not used as assumptions; generic lemmas (`hop_chain`, `resL_kprog`, tape sums) may be reused where they make no ROM claim |

## 8. Ordered proof obligations

Milestone 2: games, no bounds.
1. `CompGames`: a game type with stateful challenge oracles (pick / find phases,
   query logs), on `FiniteExperiment` (I8).
2. Games: PRG; PRF; ITSR (with the index-map shape lemmas, I13); SM-DT-TCR,
   SM-DT-TCR-C, SM-DT-DSPR (with SPprob), SM-DT-OpenPRE, SM-DT-PRE(-C),
   SM-DT-UD(-C). Each must be instantiated with DSM's actual `thash` / `hmsg`.
3. Address map `adrsEC ↦ ADRS` and the validity correspondence (I6).
4. The fixed-prefix random-function lemma (I3).
5. Restate C11/C15/C16 as PRG / PRF advantages of their existing
   distinguishers.

Milestone 3: FORS and WOTS.

6. DSM M-FORS game with committed context (I1); reductions B0–B3; DSM-T1.
7. Theorem 2 for DSM's F (OpenPRE ≤ DSPR + 3·TCR).
8. DSM WOTS-TW multi-instance game; the UD hybrids ((w−2)), TCR-C and PRE-C
   reductions; chain lemmas `ch0`, `chS`.

Milestone 4: hypertree.

9. DSM FL-SL-XMSS-MT game (all 2^68 leaves, non-adaptive, address
   restriction on the collection oracle); reduction to WOTS-TW + TCR-C(PKCO) +
   TCR-C(TRH).

Milestone 5: single-key composition.

10. Split C31's events per role and component (I9). DSM Theorem-4 analogue:
    real game ≤ Adv^PRG + Adv^KDF_SKG + Adv^PRF_SKG + Adv^KDF_MKG + Adv^PRF_MKG
    + M-FORS term + hypertree term. Expand to the twelve-term form with DSM's
    target counts.

Milestone 6: multi-key and hierarchy.

11. Computational adaptive multi-key game on `Oracle Id` (C39 base). Hybrid
    over keys with explicit loss `q_k` and simulation cost (I11).
12. Per-step derivation (keyed BLAKE3 under Smaster as a PRF, no auxiliary
    input under KS1) and the KS1 Extract/Expand hops (C70's five assumptions)
    on that game. The ChaCha20 PRG assumption is per key.
13. Final computational DSM forgery theorem. Re-run the KS1 and SPHINCS+
    vectors and the refinement checks.

Every milestone must pass the Lean build with warnings as errors, the axiom
audit, the refinement script and the claim-trace check, with no `sorry` and
no axioms.

## 9. Not claimed

No reduction, bound or game is proved by this document. It does not assert
that keyed BLAKE3 under a public key, or BLAKE3's XOF, satisfies any listed
property, and it does not transfer EasyCrypt's QROM or ROM bounds. The
EasyCrypt artifact was read, not replayed. The target counts in §6 follow
EasyCrypt's formulas with DSM's parameters and will be re-derived in Lean.
