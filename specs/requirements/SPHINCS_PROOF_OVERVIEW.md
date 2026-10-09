# DSM's SPHINCS+ security argument: overview

Status: as of 2026-10-09. This document explains DSM's SPHINCS+ security
argument end to end in plain terms. It adds no claim of its own. The
authoritative records are:

* `DSM_MODULAR_PROOF_MAP.md`: the full map; §13 records the current strategy.
* `SPHINCS_EC_CORRESPONDENCE.md`: the item-by-item correspondence between DSM
  and the published EasyCrypt proof, and the record of its replay.
* `CLAIM_TRACE.tsv`: every claim, mapped to the exact Lean theorems,
  assumptions, Rust code and tests (rows C10–C81 cited below).
* `LEAN_AXIOM_LEDGER.tsv`: the axioms every Lean theorem rests on.

Where this overview and those records differ, the records govern.

## 1. The bottom line

**What is established.** DSM's SPHINCS+ (SPX256f, BLAKE3-based) is secure
against existential forgery under chosen-message attack (EUF-CMA), *provided*:

1. the published, machine-checked SPHINCS+ proof applies to DSM's
   construction as recorded in `SPHINCS_EC_CORRESPONDENCE.md`, and
2. BLAKE3 (keyed mode and XOF) and ChaCha20 have the properties named in the
   bound below. Each property enters as a named term. None is proved.

Concretely, for every forger `A` against DSM:

    Pr[A forges against DSM]
      ≤  ITSR_mco + max(0, DSPR_F − SPprob_F) + 3·TCR_F
         + TCR-C_TRH(FORS) + TCR-C_TRCO
         + (w−2)·UD-C_F + TCR-C_F + PRE-C_F
         + TCR-C_PKCO + TCR-C_TRH(XMSS)                  (published bound)
         + Adv^PRG + Adv^KDF_SKG + Adv^PRF_SKG
         + Adv^KDF_MKG + Adv^PRF_MKG                      (DSM's own steps)

The first ten terms are the published bound, played by the published
reductions against an embedded version of `A`. The last five are DSM's own
steps, proved exactly in Lean. Every term is the advantage of a named
adversary against a named property of BLAKE3 or ChaCha20.

**What is not established.** No numerical security level ("256-bit
security") is claimed. The reductions behind the published terms have very
large running times (§7), so the bound does not turn into a number without
further work. Nothing is proved about BLAKE3 or ChaCha20 themselves.

## 2. How DSM's SPHINCS+ relates to standard SPHINCS+

DSM's FORS, WOTS+, XMSS and hypertree are SPHINCS+'s construction with the
same parameters (SPX256f: n = 32, h = 68, d = 17, h' = 4, k = 35, a = 9,
w = 16, len = 67). What DSM changes (map §5, items I1–I10):

| Change | What DSM does | How it is handled |
| --- | --- | --- |
| Hash function | Every hash is BLAKE3: keyed BLAKE3 for the tweakable hash and PRFs, BLAKE3's XOF for the message digest | This *is* the assumption: BLAKE3's properties are terms in the bound (I5) |
| Key generation | One 32-byte seed, expanded with ChaCha20, instead of three independent seeds | One exact PRG step (C11, as an advantage in C75) |
| Secret-key and message-key PRFs | Two stages: `derive_key` to get a key, then keyed BLAKE3; both take `PK.seed` as input | Exact KDF and PRF steps (C15, C16, C75) |
| Message hash | `h_msg` hashes `R ‖ PK.seed ‖ PK.root ‖ M` (as FIPS 205 does); the published scheme's message compression takes no public key | The message is embedded: the published scheme signs `PK ‖ M` (§4) |
| PRF addresses | Secrets are derived at address types 5 and 6 (FIPS 205 style); the published scheme derives them at the chain or leaf address itself | A fixed, injective renaming `prfAdr` (C80) |
| Address encoding | 32 bytes, with a reserved zero word and a 64-bit tree field; the published proof uses six abstract indices | Bijection and validity correspondence (C74, C80) |
| Signature bytes | Each authentication path is stored leaf-sibling first; the published proof lists it root-sibling first | Proved byte layout bijection that reverses each path (C81) |
| Message domain, self-check | Empty or over-long messages are rejected; each signature is verified before release | Benign: the games use legal messages only, and the self-check never fails under fixed-width hash outputs (C10) |

## 3. The strategy: reuse the published proof, prove only the differences

The identical components are already proved secure, by machine, in
EasyCrypt:

> M. Barbosa, F. Dupressoir, A. Hülsing, M. Meijers, P.-Y. Strub. *A Tight
> Security Proof for SPHINCS+, Formally Verified.* ASIACRYPT 2024. Artifact
> `MM45/FV-SPHINCSPLUS-EC` at commit `a28e4c53`, theorem
> `EUFCMA_SPHINCS_PLUS` (`SPHINCS_PLUS.ec`, line 4338).

That theorem is generic: it holds for any choice of the hash operators,
key-derivation operators and message compression that meet a short list of
axioms. So DSM does not re-prove FORS, WOTS+, XMSS or the hypertree. It shows
that DSM is one instance of that generic scheme (`E_DSM`), and proves in Lean
everything DSM changes.

The published result enters the final Lean theorem as an explicit, named
hypothesis (`premise`). It is never a Lean axiom. Lean cannot check an
EasyCrypt proof, so that hypothesis is exactly where the two tools meet (§6).

This replaced an earlier plan to re-prove every component in Lean (map §13).
The component proofs already finished stay as independent, kernel-checked
cross-checks (§8).

## 4. The argument, step by step

**Step 1: from DSM's real scheme to an idealized one (Lean, exact).**
Starting from the real game, five replacements are made, of three kinds, each
costing exactly one distinguisher's advantage:

* the ChaCha20-expanded seed is replaced by three uniform seeds
  (`Adv^PRG`; C11);
* each `derive_key` output is replaced by a uniform key
  (`Adv^KDF_SKG`, `Adv^KDF_MKG`; C15, C16);
* keyed BLAKE3 under those keys is replaced by a uniformly random function
  (`Adv^PRF_SKG`, `Adv^PRF_MKG`; C15, C16).

The result is DSM's *final world*: the same signer, but with secrets and the
message key `R` coming from truly random functions of `PK.seed ‖ ADRS` and
`PK.seed ‖ M`. Theorem `euf_cma_final` (C79) states:

    Pr[DSM real] ≤ Pr[final world] + the five advantages.

**Step 2: the final world *is* the published game (manual correspondence).**
Define the instance `E_DSM` of the published scheme
(`SPHINCS_EC_CORRESPONDENCE.md` §3):

* the published scheme's messages are `PK ‖ M`;
* its message compression `mco(R, PK ‖ M)` is DSM's: BLAKE3's XOF on
  `R ‖ PK.seed ‖ PK.root ‖ M`, cut into FORS digits, tree and leaf;
* its tweakable hash is DSM's keyed BLAKE3 on `ADRS ‖ input`;
* its secret-key PRF is ideal, read through `prfAdr`;
* its message-key PRF is ideal, read through `PK.seed ‖ M` (dropping
  `PK.root`).

DSM's forger `A` becomes a forger `A_emb` for `E_DSM`: given the public key,
it answers `A`'s signing query `M` by asking for a signature on `PK ‖ M`, and
turns `A`'s forgery on `M'` into one on `PK ‖ M'`. Freshness carries over,
since `M ↦ PK ‖ M` is one-to-one, and so does verification.

With these choices, DSM's final world for `A` and the published game for
`A_emb` are the same experiment, outcome for outcome: the same keys, the same
secrets and message keys at the same inputs, the same signer and verifier.
The published bound's two PRF terms are 0 for this instance, because its PRFs
are already ideal (record §3). DSM's real PRFs were dealt with in Step 1.

Two Lean results back the parts of this correspondence that concern DSM's
side:

* **C80** (`CompAddressValid.lean`): every hash and PRF call DSM's signer and
  key generation make, under any hash function, is at an address the
  published proof treats as valid for its type, and every PRF call is at
  `prfAdr b` for a published secret-key address `b`. `prfAdr` is one-to-one
  on those addresses.
* **C81** (`CompSigLayout.lean`): DSM's signature bytes and the published
  signature values are in exact one-to-one correspondence (lengths, offsets,
  and the reversal of every authentication path).

**Step 3: the published bound (EasyCrypt, replayed).** The published
theorem bounds the forgery probability in that game by the ten terms of §1.
The artifact was replayed on 2026-10-09 with its own pinned procedure:
EasyCrypt r2026.02 test box, Alt-Ergo 2.6.0, Z3 4.13.4. All 11 files check,
with no failure, and the sources contain no `admit` (record §9).

**Step 4: putting it together (Lean).** Theorem `euf_cma_transfer` (C79):
for every bound `B` on the final world,

    Pr[DSM real] ≤ B + the five advantages.

Taking `B` to be the published bound for `(E_DSM, A_emb)` gives §1.

## 5. What each Lean result contributes

| Claim | File | In plain terms |
| --- | --- | --- |
| C10 | `Signer.lean` | The model signer's signatures always verify, for every variant |
| C11 | `SeedHybrid.lean` | Replacing the ChaCha20 seed expansion costs exactly one PRG advantage |
| C15, C16 | `PrfHybrid.lean`, `MsgPrfHybrid.lean` | Replacing `derive_key` and keyed BLAKE3 in the two PRFs costs exactly four advantages |
| C18 | `AddressRange.lean` | Every address DSM uses fits its 32-byte encoding |
| C22 | `WotsChecksum.lean` | Two different WOTS messages always differ at a position where one digit is smaller (EasyCrypt's `two_encodings`) |
| C73 | `CompGames.lean` | The published security games, transcribed for DSM, and DSM's instances of them |
| C74 | `CompAddress.lean` | The published proof's address indices and DSM's addresses correspond one-to-one; valid addresses never collide as hash tweaks |
| C75 | `CompRestate.lean`, `CompPrfDomain.lean` | Steps C11, C15, C16 as named PRG, KDF and PRF advantages |
| C79 | `CompTransfer.lean` | The transfer theorem: `euf_cma_final`, `euf_cma_transfer` |
| C80 | `CompAddressValid.lean` | Every address DSM's signer and key generation use is valid for its type in the published proof's address space |
| C81 | `CompSigLayout.lean` | DSM's signature bytes ↔ the published proof's signature values, a proved bijection |

All are kernel-checked by Lean 4 with warnings as errors. None uses `sorry`,
`native_decide` or any axiom beyond Lean's standard three (`propext`,
`Classical.choice`, `Quot.sound`); the ledger records 2,837 checked theorems.

## 6. What is trusted

| Item | How it is established | Checked by a machine? |
| --- | --- | --- |
| DSM's own steps (Step 1, Step 4, C80, C81) | Lean proofs | Yes: the Lean kernel |
| The published bound for the generic scheme (Step 3) | EasyCrypt proof, replayed | Yes: EasyCrypt with Alt-Ergo and Z3 (the toolchain is trusted) |
| That `E_DSM` and `A_emb` are a faithful reading of the published definitions, and that the two games agree (Step 2) | `SPHINCS_EC_CORRESPONDENCE.md`, written line by line against the artifact | **No.** It is a correspondence between two formalisms, checked by reading |
| BLAKE3 and ChaCha20 have the named properties | Assumed, as named terms in the bound | No, and not claimed |
| The Rust code computes what the Lean model computes | Refinement checks: test vectors from the Rust crate replayed against the Lean model, plus negative controls | By test, not by universal proof |

## 7. What is not claimed

* **No numerical security level.** The published reductions build the whole
  key structure up front, about 2^83.2 `thash` evaluations for these
  parameters (map §7). Neither the published proof nor DSM bounds the
  reductions' running time. So each term must be read as "the advantage of an
  adversary of that size", and the bound is not converted into bits of
  security.
* **No polynomial-time claim** for any reduction.
* **No property of BLAKE3 or ChaCha20** is proved: keyed BLAKE3 under a
  public key, BLAKE3's XOF and ChaCha20 as a PRG are assumptions.
* **No quantum (QROM) bound** is transferred.
* **The Rust implementation** is related to the Lean model by test vectors,
  not by a proof over all inputs.

## 8. Independent cross-checks

Before the strategy changed, three parts of the published proof were
re-proved in Lean against DSM's own game framework. They are redundant with
the published result and are kept as kernel-checked cross-checks, with
explicit query budgets the published proof does not state:

* **C76**: Theorem 2 (OpenPRE from DSPR and 3·TCR), for DSM's F;
* **C77, C78**: the WOTS-TW bound, `(w−2)·UD-C + TCR-C + PRE-C`, for an
  abstract WOTS-TW setting.

The other planned re-proofs (FORS reductions, the DSM instance of WOTS-TW,
the hypertree reduction) were withdrawn as unnecessary.

## 9. Reproducing the checks

From the repository root:

    bash scripts/check_sphincs_refinement.sh   # Lean build (warnings as errors), Rust vectors, cross-checks, controls
    python3 scripts/lean_axiom_audit.py        # regenerates LEAN_AXIOM_LEDGER.tsv
    python3 scripts/check_claim_trace.py       # every claim's theorems exist and use core axioms only

The EasyCrypt replay: check out `MM45/FV-SPHINCSPLUS-EC` at
`a28e4c53897a4bb57b575a177225862d48f824b7` and run `make docker-check`
(record §9).

## 10. Status

Nothing further is owed in Lean for the transfer. The one step not checked by
a machine is the correspondence of Step 2, recorded in
`SPHINCS_EC_CORRESPONDENCE.md`.
