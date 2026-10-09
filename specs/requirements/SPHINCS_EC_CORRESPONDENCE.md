# DSM ↔ EasyCrypt SPHINCS+: the transfer premise, item by item

Status: record for obligation T3/T4 of the delta strategy
(`DSM_MODULAR_PROOF_MAP.md` §13). It states exactly how DSM's construction is
read as an instance of the published SPHINCS+ proof, so that the auditors can
check the premise of `euf_cma_transfer` (`lean4/Sphincs/CompTransfer.lean`).
It is a manual correspondence between two formalisms (EasyCrypt and Lean). No
tool checks it. It adds no axiom to DSM's Lean development.

**Source.** `MM45/FV-SPHINCSPLUS-EC` at `a28e4c53897a4bb57b575a177225862d48f824b7`.
Paths below are under `proofs/`. Line numbers are at that commit.
**Replay.** Done on 2026-10-09: all 11 files check, no failure (§9).

## 1. What is transferred

`SPHINCS_PLUS.ec` line 4338, `EUFCMA_SPHINCS_PLUS`: for every adversary `A`
with lossless `forge` (`A_forge_ll`, line 1679),

    Pr[EUF_CMA(SPHINCS_PLUS, A)] ≤ PRF_skg + PRF_mkg + ITSR_mco
        + max(0, DSPR_F − SPprob_F) + 3·TCR_F            (FORS leaves)
        + TCR-C_TRH (FORS) + TCR-C_TRCO
        + (w−2)·UD-C_F + TCR-C_F + PRE-C_F                (WOTS chains)
        + TCR-C_PKCO + TCR-C_TRH (XMSS)

Each term is the advantage of a named EasyCrypt reduction module built from
`A`. The theorem is generic in the parameters, in the types `msg`, `mseed`,
`sseed`, `pseed`, `mkey`, and in the operators `skg`, `mkg`, `mco`, `thfc`,
`encode_msgWOTS` and `ch`, subject to the axioms listed in §4.

The Lean side (`euf_cma_transfer`) proves:

    Pr[DSM real] ≤ B + Adv^PRF_MKG + Adv^KDF_MKG + Adv^PRF_SKG + Adv^KDF_SKG + Adv^PRG

for every bound `B` on DSM's final world (PRG and PRF hops done). The premise
is that `B` is the right-hand side above, for the instance `E_DSM` of §3 and
the embedded forger `A_emb` of §6, whose two PRF terms are 0 (§3).

## 2. Parameters (SPX256f)

| EasyCrypt | Line | Value | DSM (`Model.lean`) |
| --- | --- | --- | --- |
| `n` (bytes) | 25 | 32 | `params .spx256f` n = 32 |
| `k`, `a`, `t = 2^a` | 30–36 | 35, 9, 512 | k = 35, a = 9 |
| `log2_w`, `w` | 41–44 | 4, 16 | base 16 in `wotsDigits`; chains end at 15 |
| `len1`, `len2`, `len` | 47–53 | 64, 3, 67 | `Params.len = 2n + 3 = 67` |
| `h'`, `l' = 2^h'`, `d`, `h = h'·d`, `l = 2^h` | 58–77 | 4, 16, 17, 68, 2^68 | `Params.hp = h / d = 4`, d = 17, h = 68 |
| `chtype`, `pkcotype`, `trhxtype`, `trhftype`, `trcotype` | 82–106 | 0, 1, 2, 3, 4 | `Adrs.kind` 0–4 (PRF kinds 5, 6, see §3) |

## 3. The instance `E_DSM`

**Encodings.** A `dgstblock` (`8n` bits) is an n-byte string, read
most-significant bit first in each byte (`toBits`, `toBytes`). A `pseed` is
the n-byte `PK.seed`. An `adrs` (six indices, `HashAddresses.eca`) is DSM's
`Adrs` through `ofEc` / `ecIdx`. Index order: hash/breadth, chain/height,
key pair, type, tree, layer (C74).

| EasyCrypt operator | Instance |
| --- | --- |
| `thfc ℓ ps ad x` (line 434), hence `f`, `trh`, `pkco`, `trco` | `toBits(thash(K_th(ps), ofEc ad, toBytes x))`: keyed BLAKE3 under `derive_key("DSM/sphincs/v2/thash", ps)` on `ADRS ‖ x` (`thc`, C73; `thc_thash`) |
| `ch g ps ad s i x` (`WOTS_TW_ES.ec` line 498) | DSM's `chain` (`Model.lean`): step `j` hashes at `hash := s + j` |
| `encode_msgWOTS m` (line 569) | `wotsDigits(toBytes m)`: 64 base-16 digits and 3 checksum digits |
| `msg` | byte strings of length ≤ 2n + `maxMessageBytes`; the forger signs only `pk ‖ M` (§6) |
| `mkey` | n bytes (`R`) |
| `mco mk m` (`FORS_ES.ec` line 412) | for `m = PK.seed ‖ PK.root ‖ M`: `splitDigest(h_msg(mk, PK.seed, PK.root, M)) = (md, tree, leaf)`; `cm` = the first `k·a` bits of `md`, MSB first; `idx = tree·2^h' + leaf` (`mco`, `mco_verifier`, C73) |
| `sseed`, `skg ss (ps, ad)`, `dsseed` | **ideal**: `ss` is a function on `pseed × adrs`, `skg ss x = ss x`. `dsseed` is the law of `(ps, ad) ↦ F(ps ‖ prfAdr(ofEc ad).bytes)` for `F` uniform on (n+32)-byte inputs (DSM's final world). `prfAdr` sets kind 0 → 5 and kind 3 → 6 (chain 0) and is the identity on kinds 1, 2, 4. It is injective on valid addresses (the kind separates the images; C74 within a kind), so `dsseed` is uniform on functions. |
| `mseed`, `mkg ms m`, `dmseed` | **ideal, read through the key's seed**: `ms` is a function on byte strings of length ≤ n + `maxMessageBytes`, `mkg ms m = ms(dropRoot m)` with `dropRoot(PK.seed ‖ PK.root ‖ M) = PK.seed ‖ M`, and `dmseed` is the law of DSM's final-world `H` (uniform on such functions) |

**The two PRF terms are 0.**
* `PRF_skg`: with `dsseed` uniform on functions, EasyCrypt's real and ideal
  PRF oracles (`KeyedHashFunctions.eca`, `PRF`/`O_PRF_Default`) have the same
  law for every distinguisher: a uniformly random function, evaluated up
  front or lazily.
* `PRF_mkg`: the term is for one distinguisher, `R_MKGPRF_EUFCMA(A_emb)`
  (`SPHINCS_PLUS.ec` 1214–1300). It queries its oracle only inside its
  signing oracle, on the messages `A_emb` asks. Those are all
  `pk ‖ M` for the one public key of the run (§6). On that set `dropRoot` is
  injective, so `m ↦ ms(dropRoot m)` is a uniformly random function there, and
  both oracles have the same law.

These are statements about EasyCrypt's games, argued here. They are not
checked by any tool. DSM's actual SKG and MKG are handled by DSM's own exact
hops instead (C11, C15, C16; their advantages remain as terms).

With this instance, DSM's final world and `E_DSM`'s game for `A_emb` agree
pointwise: the same key distribution, the same secrets and message keys at the
same inputs, and the same signer and verifier. No step of the transfer is a
distributional argument on the Lean side.

## 4. EasyCrypt axioms, discharged for `E_DSM`

| Axiom | File | DSM |
| --- | --- | --- |
| `dist_adrstypes` | all three | kinds 0–4 distinct, by `decide` (C74) |
| `valid_widxvals_idxvals`, `valid_xidxvals_idxvals`, `valid_fidxvals_idxvals` | WOTS, XMSS, FORS | `EcValid` and the per-shape lemmas `ecValid_*` (C74) |
| `ch0`, `chS` | `WOTS_TW_ES.ec` 504, 511 | DSM's `chain` (`Model.lean`) returns its input after 0 steps by definition; `chain_composes` (`Proofs.lean`) splits a chain into consecutive runs, which gives the last-step form |
| `two_encodings` | `WOTS_TW_ES.ec` 572 | `wots_checksum_decreases_of_ne` (C22) |
| `in_collection` | `TweakableHashFunctions.eca` | one function `thc` for every input length (C73) |
| ITSR shape of `g` (`size_g`, `eqiks_g`, `neqisvs_g`, `rng_iks_g`, `rng_sv_g`) | `FORS_ES.ec` 421 | `itsrG_*` (C73) |
| lossless distributions (`d*_ll`) | all | uniform finite distributions |
| `A_forge_ll` | `SPHINCS_PLUS.ec` 1679 | DSM strategies are total and fuel-bounded (`SecurityGames.run`) |

## 5. Algorithms

| EasyCrypt procedure | DSM (`Model.lean`) | Correspondence |
| --- | --- | --- |
| `SPHINCS_PLUS.keygen` (957) | `generateKeypair` after the PRG hop | `ms, ss, ps` independent and uniform (DSM after C11); `root = gen_root(ss, ps)` = `xmssNode … {layer := d−1} 0 h'` |
| `FL_SL_XMSS_MT_ES.gen_root` (1537) | `xmssNode` at layer d−1, tree 0, height h' | leaves: WOTS keys at `(layer, tree, kind 0, keypair j)`, compressed by `pkco` at kind 1 (`wotsPkgen`, `wotsCompress`) |
| `WOTS_TW_ES.gen_skWOTS` (2039) | `wotsSign`/`wotsPkgen` secrets | `skg ss (ps, chain address, hash 0)` = `prf` at kind 5, same fields (`prfAdr`) |
| `pkWOTS_from_skWOTS`, `sign`, `pkWOTS_from_sigWOTS` (2053–2155) | `wotsPkgen`, `wotsSign`, `wotsPkFromSig` | chain `j` from 0 to `w−1`, to `d_j`, from `d_j` for `w−1−d_j` steps, hash index from the start position |
| Merkle trees: `trhi`, `val_bt_trh`, `cons_ap_trh`, `val_ap_trh` (`FL_SL_XMSS_MT_ES.ec` 653–706; `FORS_ES.ec` 660–710) | `xmssNode`, `forsNode`, `authWalk` | node at height `h`, breadth `b` hashed at `(chain := h, hash := b)` on `left ‖ right`; leaves at height 0 |
| `FL_FORS_ES.gen_leaves_single_tree`, `gen_pkFORS`, `sign`, `pkFORS_from_sigFORSTW` (`FORS_ES.ec` 1523–1666) | `forsSecret`, `forsNode`, `forsSign`, `forsPkFromSig` | leaf `i·t + idx` at `(kind 3, height 0, index i·t+idx)`; secret `skg` there = `prf` at kind 6; digit `i` = `bs2int(rev(take a (drop a·i cm)))` = `base2b(md, a, k)[i]` (MSB first); roots compressed by `trco` at kind 4, same key pair |
| `M_FORS_ES.sign` (1730) | `sign`, lines `r`/`digest`/`indices`/`forsSign` | `mk = mkg ms m`, `(cm, idx) = mco mk m`, `(tidx, kpidx) = edivz idx l'`, FORS at `(layer 0, tree tidx, kind 3, keypair kpidx)` |
| `FL_SL_XMSS_MT_ES.sign` (1574), `root_from_sigFLSLXMSSMTTW` (1620) | `htSign`, `htSignTail`, `htRoot`, `htRootTail` | layer `i`: `(tidx, kpidx) = edivz tidx l'` (`nextLayer`); WOTS at `(layer i, tree tidx, kind 0, keypair kpidx)` signs the layer below's root |
| `SPHINCS_PLUS.sign` (984), `verify` (1022) | `sign`, `verify` | as above; DSM's self-check never fails under `OutputWidths` (C10) |
| signature `(mk, sigFORSTW, sigFLSLXMSSMTTW)` | `R ‖ fors ‖ ht`, fixed widths (`Params.sigBytes`) | a fixed bijection on well-formed bytes. EasyCrypt lists each authentication path root first (`cons_ap`, `MerkleTrees.ec` 12); DSM stores it leaf first. The bijection reverses each path. |

## 6. Games and the embedded forger

EasyCrypt's `EUF_CMA(S, A, O_CMA_Default)`: key generation, an adaptive
signing oracle on any `msg`, and a win if `verify` holds on a message never
queried. DSM's game (`SecurityGames.lean`): the same, with a signing budget
and legal messages only (non-empty, ≤ `maxMessageBytes`).

`A_emb`, given `(root, ps)`, forms `pk = ps ‖ root` and runs DSM's strategy on
it. For a legal query `M` it asks `sign(pk ‖ M)` and returns the signature's
bytes; for an illegal one it answers `none` itself. It outputs `pk ‖ M'` and
the parsed forgery. Freshness is preserved, since `M ↦ pk ‖ M` is injective.
Verification agrees, since `verify_EC(pk, pk ‖ M', σ) = verify_DSM(pk, M', bytes σ)`.
A malformed forgery loses in both games. `A_emb` is lossless.

DSM's final world for strategy `A` and `E_DSM`'s game for `A_emb` agree
pointwise (§3). The premise of `euf_cma_transfer` is then exactly §1 for
`(E_DSM, A_emb)`.

## 7. The terms, as DSM games

The ten remaining terms are EasyCrypt games on `E_DSM`'s operators, played by
EasyCrypt's reductions of `A_emb`. Their Lean renderings, for comparison, are
Milestone 2's DSM instances (C73): ITSR on `mco` with input `pk ‖ M`
(`itsrG`); DSPR/SPprob/TCR on F (`dsmDsprAdv`, `dsmTcrF`); TCR-C on TRH,
TRCO, PKCO (`dsmTcrC` at 2n, k·n, len·n bytes); UD-C, TCR-C, PRE-C on F
(`dsmUdCAdv`, `dsmTcrC n`, `dsmPreC`). The reductions themselves are EasyCrypt
modules and are not rendered in Lean. Theorem 2 (C76) and the WOTS-TW bound
(C78) re-prove terms 4–5 and 8–10 in Lean, as an independent check.

## 8. Owed, and not claimed

Owed: the per-kind ranges of
the addresses DSM's signer issues (C18 proves only `InRange`); the signature
parse bijection in Lean (T5).

Not claimed: that keyed BLAKE3, BLAKE3's XOF or ChaCha20 satisfies any of the
listed properties; any numerical security level; anything about EasyCrypt's
reduction running times (none are bounded; see the map, §7).

## 9. Replay

Replayed on 2026-10-09 (UTC) on the maintainer's machine (Apple Silicon, Docker
Desktop), with the artifact's own procedure:

* source: `MM45/FV-SPHINCSPLUS-EC` checked out at `a28e4c53897a4bb57b575a177225862d48f824b7`;
* `make docker-check`: an image built `FROM ghcr.io/easycrypt/ec-test-box:r2026.02`
  (local image `sha256:ddc3b360a149…`), running `easycrypt runtest config/tests.config`
  over `proofs/`;
* provers as pinned in `easycrypt.project`: Alt-Ergo 2.6.0 and Z3 4.13.4 (both
  present in the image), timeout 3;
* result: **11 files, 11 success, 0 failure**, in 26 min 02 s. The 11 files are
  all of `proofs/`: `BinaryTrees.ec`, `FL_SL_XMSS_MT_ES.ec`, `FORS_ES.ec`,
  `MerkleTrees.ec`, `PRE_From_SPR_DSPR.ec`, `SPHINCS_PLUS.ec`, `WOTS_TW_ES.ec`,
  `HashAddresses.eca`, `KeyedHashFunctions.eca`, `OpenPRE_From_TCR_DSPR_THF.eca`,
  `TweakableHashFunctions.eca`.
* No `admit` occurs in the sources (searched). The development's own axioms
  are the parameter and operator axioms of §4, and `A_forge_ll`.

This replay establishes that the published development checks with its
pinned toolchain. It does not check §3–§7, which remain a manual
correspondence.
