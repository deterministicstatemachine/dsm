# SPHINCS+ primitive roles in DSM's BLAKE3 instantiation

Status: analysis, audit-prep 2026-10-07. Source: `crates/dsm-sphincs/src/lib.rs`
at the frozen audit commit. No security level or reduction is claimed here; this
records, per role, what the tight SPHINCS+ proof assumes, what DSM computes,
and what is still owed.

The tight proof is Hülsing and Kudinov, "Recovering the tight security proof of
SPHINCS+" (ASIACRYPT 2022, ePrint 2022/346), formally verified in EasyCrypt by
Barbosa, Dupressoir, Hülsing, Meijers and Strub (ePrint 2024/910). It reduces
EUF-CMA to: the tweakable hash family `Th` (F, H, T_l) being target-collision
resistant, decisional second-preimage resistant, preimage resistant and
undetectable in the multi-target setting; `H_msg` being interleaved
target-subset resilient (ITSR); and `PRF`, `PRF_msg` being PRFs. Its QROM
bounds for those properties model the underlying hash as a random oracle.

## The six roles, as implemented

| Role | Code | Key | Input (byte layout) | Output |
| --- | --- | --- | --- | --- |
| Seed expansion | `generate_keypair_from_seed` | — | ChaCha20Rng(seed32) | 3n bytes: SK.seed ‖ SK.prf ‖ PK.seed |
| Key derivation | `derive_key` | — | BLAKE3 derive_key(context, material) | 32 bytes |
| `PRF` | `prf` | `K_prf = derive_key("DSM/sphincs/v2/prf", SK.seed)` — **secret** | PK.seed (n) ‖ ADRS (32) | keyed BLAKE3, first n bytes |
| `PRF_msg` | `prf_msg` | `K_msg = derive_key("DSM/sphincs/v2/prf-msg", SK.prf)` — **secret** | opt_rand = PK.seed (n) ‖ M | keyed BLAKE3, first n bytes |
| `Th` = F, H, T_l | `thash` | `K_th = derive_key("DSM/sphincs/v2/thash", PK.seed)` — **public** | ADRS (32) ‖ M, M = n, 2n, len·n or k·n bytes by call site | keyed BLAKE3, first n bytes |
| `H_msg` | `h_msg` | none (derive-key mode, context "DSM/sphincs/v2/h-msg") | R (n) ‖ PK.seed (n) ‖ PK.root (n) ‖ M | XOF, m bytes (34 for SPX128f, 49 for SPX256f) |

Structural properties that hold by inspection and are checked by the existing
Lean/vector evidence (`Blake3Checks`, `CrossCheck`, `SPHINCS_REFINEMENT.md`):

- Every role's input has an unambiguous split: all fields are fixed width
  except a single variable-length field placed last (`M` in `PRF_msg` and
  `H_msg`). Within `Th`, the message width is fixed per call site and the
  32-byte ADRS names the call site.
- Roles are separated twice: by BLAKE3 mode flag (keyed-hash for PRF, PRF_msg
  and Th; derive-key-material for H_msg) and by four distinct, hard-coded KDF
  context strings, one per role.
- Every ADRS is the full 32-byte form, not FIPS 205's 22-byte compressed form.

## Role by role: what is assumed, what BLAKE3 offers, what is owed

**PRF and PRF_msg (secret keys).** The proof needs PRF security under a
uniformly random key. DSM's key is `derive_key(context, secret seed)`, so the
argument is two hybrids: KDF output indistinguishable from uniform (the
BLAKE3 specification's derive-key claim), then keyed BLAKE3 as a PRF (its
keyed-hash claim). This is the closest match. Two caveats: the claims are design
claims of the BLAKE3 authors, not reductions to a smaller assumption; and the
key carries only the seed's entropy (n bytes: 128 bits for SPX128f), which is
consistent with the target level but must appear in the bound.

**Proved (audit-prep, 2026-10-07).** Both secret-keyed roles are replaced by
truly random functions in four exact hops, each with an explicit
distinguisher proved to reproduce the previous game (Lean, core axioms only):

| Hop | Replaces | Theorem | Gap term |
| --- | --- | --- | --- |
| 1 | ChaCha20 expansion of the master seed by uniform 3n bytes | `seed_prg_hybrid_bound` | PRG advantage of `seedDistinguisher` |
| 2a | `derive_key("…/prf", SK.seed)` by a uniform key | `prf_key_hybrid_bound` | KDF advantage of `keyDistinguisher` |
| 2b | keyed BLAKE3 under that key by a random function on PK.seed ‖ ADRS | `prf_function_hybrid_bound` | PRF advantage of `functionDistinguisher` |
| 3a | `derive_key("…/prf-msg", SK.prf)` by a uniform key | `msg_key_hybrid_bound` | KDF advantage of `msgKeyDistinguisher` |
| 3b | keyed BLAKE3 computing R by a random function on PK.seed ‖ M | `msg_function_hybrid_bound` | PRF advantage of `msgFunctionDistinguisher` |

After hop 3b neither SK.seed nor SK.prf appears in the game. What remains
assumed for these roles is exactly BLAKE3's stated claims: `derive_key` output
indistinguishable from uniform, and keyed BLAKE3 a PRF. The simulation step
for every signer and verifier component is `OracleAgree.lean`.

**Th = F, H, T_l (public key).** This is where the BLAKE3 PRF claim says
nothing. `K_th` is computed from PK.seed, which is public, so keyed BLAKE3 here
is a fixed public hash function per key pair. The properties the proof needs
(multi-target TCR, DSPR, PRE, UD with ADRS as the tweak) are hash-function
properties, and the BLAKE3 specification does not state them for keyed mode
with a public key. The usual route is the one HK22 use for the standard
instantiations: treat the hash as a (quantum-accessible) random oracle and
apply their generic bounds. For DSM that needs an argument that keyed BLAKE3,
as a function of (PK.seed, ADRS, M), can be modelled that way: either an
indifferentiability result for BLAKE3's mode over its compression function, or
a direct analysis of this instantiation. Neither exists in the BLAKE3
specification or in DSM's evidence. **This is the main open cryptographic
obligation, and the best use of an external cryptographer's time.**

**H_msg (no key).** The proof needs ITSR, bounded in the QROM with H_msg as a
random oracle. The standard SHA-2 profiles wrap the hash in MGF1 over a
SHA-256/512 prehash (FIPS 205 §11.2), partly because of Merkle–Damgård
structure; BLAKE3's XOF has no length extension (the root node is finalized
with a distinct flag), so the direct construction is plausible, but the same
modelling argument as for Th is owed. The output widths match FIPS 205 (34 and
49 bytes).

**Seed expansion.** ChaCha20 as a PRG from one 32-byte master seed;
`SeedHybrid.lean` already proves the exact PRG-hybrid step. ChaCha20 PRG
hardness itself remains an assumption.

**Key derivation from PK.seed.** `derive_key` on public input is not a KDF use
in the security sense; it only fixes which public hash function `Th` is. Its
"KDF" property is irrelevant there and should not be cited for Th.

## What this means for the audit scope

1. The PRF rows can be closed in writing before the audit (two hybrids, stated
   advantage terms). They need no new cryptographic insight.
2. The Th and H_msg rows need a cryptographer's judgement on the modelling of
   BLAKE3 (random-oracle or indifferentiability argument). That is what to
   ask OSTIF to scope explicitly in item 7, rather than a general review of the
   signer's code.
3. No row is a known weakness. The gap is that the published SPHINCS+ proofs
   do not transfer to these primitive roles automatically.
