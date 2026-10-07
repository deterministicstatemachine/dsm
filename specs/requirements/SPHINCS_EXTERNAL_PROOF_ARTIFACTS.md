# External proof artifacts inspected, 2026-10-06

This is a source-inspection record, not a claim that external proofs have been
run or instantiated for DSM. The repositories were downloaded read-only into
the local task workspace. No external proof axiom was added to DSM's Lean proofs.

## Computational-security reduction

The primary artifact accompanying *A Tight Security Proof for SPHINCS+, Formally
Verified* is [MM45/FV-SPHINCSPLUS-EC](https://github.com/MM45/FV-SPHINCSPLUS-EC),
inspected at `a28e4c53897a4bb57b575a177225862d48f824b7`.
The [paper](https://eprint.iacr.org/2024/910) describes its EasyCrypt development.

In `proofs/SPHINCS_PLUS.ec`, `EUFCMA_SPHINCS_PLUS` (line 4338) bounds forgery by
actual reduction adversaries against seed/message PRFs, message-compression
ITSR, and tweakable-hash properties including DSPR, TCR, PRE and UD. The reductions
are implemented modules, not an assumption that every forgery is a bad event.
`FORS_ES.ec`, `WOTS_TW_ES.ec` and `FL_SL_XMSS_MT_ES.ec` supply component proofs.
The pinned README specifies EasyCrypt 2026.02, Z3 4.13.4 and Alt-Ergo 2.6.0.
EasyCrypt is not installed in this workspace; this external proof has not been
locally replayed.

The following transfer obligations were identified by reading the actual scripts:

| Artifact definition | DSM obligation before the theorem can be used |
| --- | --- |
| `keygen`, lines 971–973, samples `ms`, `ss`, `ps` separately | Add an explicit computational hybrid for DSM's one 32-byte master seed expanded by the actual ChaCha20Rng. Independent sampling is a hybrid destination, never the deployed starting game. |
| `mkg : mseed -> msg -> mkey`, line 409; FORS signing evaluates `mkg ms m` | Determinism is already modeled. Match DSM's derived-key BLAKE3 PRF-msg including public seed input and its dependence on the generated public key. Repeated messages must retain the same answer in both games. |
| `skg : sseed -> (pseed * adrs) -> dgstblock`, line 390 | Connect the exact derived-key/keyed BLAKE3 call, public seed, address bytes and truncation to this family. |
| `thfc`, line 434, is a public-parameter/tweak family | Establish the stated hash-family properties for DSM's public-seed-derived BLAKE3 key; a secret-key PRF assumption does not justify this family. |
| `adrs_len = 6`, line 19, uses abstract integer coordinates | Prove a byte-level mapping into DSM's eight big-endian u32 words, reserved word, 64-bit tree field, type clearing and PRF address kinds. Coordinate injection cannot be presumed from matching names. |
| Message compression `mco` and its ITSR experiment | Preserve DSM's actual XOF inputs `R || PK.seed || PK.root || message`, parameter-dependent output widths and index decoding. |
| Abstract primitive families and adversary modules | Prove adaptations and budget accounting for their correlated use of one BLAKE3 construction. Distinct context labels are not independent random oracles. No quantum transfer follows from this classical theorem. |

These scripts provide a concrete reusable reduction structure. They do not
provide a BLAKE3-specific proof or a numerical DSM security level. DSM's new Lean
wrapper extraction proves a smaller, separate result: a fresh accepted canonical
certificate yields a fresh underlying signed digest or an explicit hash collision,
with at most q+1 hash calls. Its finite-transcript advantage bound does not replace
the adaptive primitive reductions in this external artifact.

## Direct AArch64 machine-code verification

The primary framework [awslabs/s2n-bignum](https://github.com/awslabs/s2n-bignum)
was inspected at `4d1356a7470663c752660a59375dc3a9ef548428`.
`arm/proofs/bignum_mux.ml` uses `define_assert_from_elf` to compare object bytes
with the instruction sequence proved by `ARM_MK_EXEC_RULE` and HOL Light Hoare
triples. `arm/tutorial/safety.ml` demonstrates separate functional and safety
theorems. The latter quantify an event function depending only on public inputs
and require every load/store to be within declared readable/writable regions.

This establishes a more direct route than proving the complete Rust-to-LLVM-to-NDK
compiler pipeline: prove the actual pinned artifact's instruction bytes against
the specification. A helper rebuilt separately, or a proof of different assembly,
does not establish equivalence of the deployed SDK. A DSM proof would still need
its instruction ranges, relocations, ABI, imported callees, memory permissions,
stack behavior, and a bridge to the existing Lean specification. HOL Light proofs
are not automatically Lean kernel proofs. Neither framework nor loader has been
executed against DSM in this inspection.

The [soundness document](https://github.com/awslabs/s2n-bignum/blob/main/SOUNDNESS.md)
explicitly distinguishes instruction/memory trace independence from hardware
timing and notes ISA/decoder, loader and execution-environment assumptions. JNI,
allocator failure, foreign retention, erasure, speculation and hardware leakage
must not disappear into a claimed kernel theorem.

## Rust source refinement

[Aeneas's cryptographic verification guide](https://github.com/AeneasVerif/aeneas/blob/main/documentation/crypto-verification.md)
provides an implementation-shaped auxiliary specification between mathematical
specification and generated Rust semantics. This is directly applicable to the
remaining `base_2b` digit-value equivalence. DSM now proves termination and exact
output length of both extracted Rust parser loops under the exact input bit
budget. Digit-value equivalence and concrete allocator/binary behavior remain
separate obligations. The guide supplies techniques, not proofs of DSM.

## BLAKE3 model cross-reference

Official sources inspected: [specification](https://github.com/BLAKE3-team/BLAKE3-specs/blob/ac784c9f22a48327782f042ec2f4d8126b3b1744/blake3.tex)
at `ac784c9f22a48327782f042ec2f4d8126b3b1744`, and
[reference implementation](https://github.com/BLAKE3-team/BLAKE3/blob/f55849f89cd85083c1c9daa2c5de20766f309c00/reference_impl/reference_impl.rs)
and official vectors at `f55849f89cd85083c1c9daa2c5de20766f309c00`.
DSM actually resolves crate **1.8.5**, registry checksum
`0aa83c34e62843d924f905e0f5c866eb1dd6545fc4d719e803d9ba6030371fce`.
The downloaded upstream head is a reference source, not a substitute for that
locked production dependency. Its local `src/lib.rs` was also inspected.

`lean4/Sphincs/Blake3.lean` now defines an executable compression/tree/XOF model
using UInt32 arithmetic and no external hash implementation. The existing
`Request` model remains available for abstract functional proofs. `evaluate`
connects its BLAKE3 requests to the new concrete model, rejecting malformed keys
and unsupported modes. ChaCha20 expansion remains a separate mode and obligation.

| Actual DSM operation | Existing model | Concrete BLAKE3 lowering |
| --- | --- | --- |
| `derive_key` / `Hasher::new_derive_key` | request mode 0 | `contextKey`: IV + context-mode flag 32; material: context result as key + material-mode flag 64; take 32 output bytes |
| `keyed` / `Hasher::new_keyed` | request mode 1 | 32 key bytes parsed as eight little-endian words; keyed-mode flag 16; take n bytes |
| `thash` | `thash` request | Derived public-seed key; exact `ADRS || input` bytes |
| `prf` | `prf` request | Derived secret-seed key; exact `PK.seed || ADRS` bytes |
| `prf_msg` | signing's derived message key and keyed request | Exact deterministic `PK.seed || message`; no extra randomized input |
| `h_msg` / `finalize_xof` | request mode 2 / `hmsg` | Same two-stage derive construction; exact `R || PK.seed || PK.root || message`; parameter-dependent XOF length |
| certificate/device wrapper hashing | request mode 4 | IV, ordinary hash mode, existing canonical wrapper bytes |

Cross-references in the official reference source: `g`/`round`/`compress` map to
`mix`/`round`/`compress`; `Output::chaining_value` and `root_output_bytes` map to
`Output.chaining` and `Output.root`; `ChunkState` maps to `chunk`; parent CV
stack merging maps to `parent`, `merge` and `tree`. Root output uses its own
output-block counter. DSM address serialization remains big-endian; BLAKE3
compression words and output bytes are little-endian. Those are distinct layers.

Kernel-checked wiring theorems connect `deriveKey`, `thash`, `prf` and `hmsg`
requests to these concrete definitions. `derive_xof_same_32` proves that mode 0
and mode 2 are identical at 32 output bytes for equal context/material. Context
string distinctness is proved; independence of derived outputs is not implied.
`Blake3Proofs.lean` proves exact output widths for the concrete model and all
accepted requests, plus prefix consistency of arbitrary root XOF lengths. These
theorems require no cryptographic assumption. The official-vector and
Rust-transcript comparisons are tests, not universal proofs of compression
correctness, tree correctness or the Rust crate's equivalence to the model.
Defaulted array accesses still require a separate shape-safety proof.

The specification's security target is 128 bits, despite its 256-bit key width.
Its displayed mode-indifferentiability bound explicitly restricts output length
to at most 256 bits. DSM's deployed `SPX128f` and `SPX256f` H_msg lengths are
**34 and 49 bytes**, now computed by a kernel-checked theorem. That restricted
bound therefore cannot simply be used for these XOF calls. The paper separately
discusses full outputs; a transfer proof is still required. This does not establish
an attack, or determine DSM's final security level.

Remaining computational obligations: adapt public-key-dependent message
compression, correlated KDF outputs, truncation, multi-target/different-tweak
hash-family experiments and ChaCha20 expansion to the SPHINCS reduction. A
concrete algorithm definition alone does not prove those properties, and no
independent-random-oracle premise was introduced here.

## SHA-2 comparison (2026-10-07)

The comparison source is [FIPS 205, sections 11.2.1–11.2.2](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf), the standardized SLH-DSA constructions derived from SPHINCS+. This is a construction reference, not an assertion that the EasyCrypt artifact already instantiates these standard functions or proves SHA-2 itself secure.

| Role | Standard SHA2-128 | Standard SHA2-192/256 | Actual DSM BLAKE3 |
| --- | --- | --- | --- |
| Message compression | SHA-256 prehash followed by MGF1-SHA-256, binding R, seed, root, message | Corresponding SHA-512/MGF1 construction | Derive-mode XOF directly over R, seed, root, message |
| Message randomizer | Truncated HMAC-SHA-256 | Truncated HMAC-SHA-512 | Truncated keyed BLAKE3 under a context-derived SK.prf key |
| Secret element PRF | Seed-prefixed SHA-256 with secret seed appended | Same | Keyed BLAKE3 under a context-derived SK.seed key |
| F | Seed-prefixed, padded SHA-256 | Same | Public-seed-derived keyed BLAKE3 |
| H and public-key compression | Seed-prefixed, padded SHA-256 | Seed-prefixed, padded SHA-512 | Public-seed-derived keyed BLAKE3 |
| Address encoding | Compressed 22 bytes | Compressed 22 bytes | Full 32 bytes |

Transfer consequence: WOTS/FORS/hypertree structural reductions can be reused only after establishing the matching primitive-family interfaces and assumptions. HMAC arguments do not automatically justify keyed BLAKE3; MGF1 arguments do not automatically justify DSM's derive-mode XOF; seed-prefix arguments do not automatically justify public-seed-derived keys. Explicit simulations/reductions must preserve the exact input encodings and public/secret key roles. The larger standard profiles change multiple primitive roles to SHA-512, so replacing the comparison with only SHA-256 would obscure relevant assumptions. No algorithm change, numerical bound, new cryptographic axiom or security-transfer theorem is claimed by this comparison.

## Pinned substitution boundary and first hybrid

The comparison is between primitive instantiations, not a demand that SHA and
BLAKE3 produce equal bytes. The mathematical tree/composition model is unchanged.
The EasyCrypt artifact's abstract interfaces are the target; the standard's SHA-2
implementation is the reference showing how those interfaces are instantiated.

| Narrow boundary | DSM definition pinned | What is established / next obligation |
| --- | --- | --- |
| Seed distribution | `generateKeypair`, mode 3, 32-byte master to 3n-byte expansion | `SeedHybrid.lean`: actual game equals explicit seed-challenge simulation; exact PRG-gap bound to uniform 3n-byte destination. Efficient distinguisher cost and actual ChaCha20 PRG hardness remain open. |
| Secret primitive families | `deriveKey(prf)` + `prf`; `deriveKey(prf-msg)` + deterministic keyed request | Concrete BLAKE3 wiring/output checks exist. Joint KDF/keyed-hash PRF reductions and correlated use of public seed remain open. |
| Public tweakable family | `deriveKey(thash, PK.seed)` + `ADRS || M` | Public key is computable. Establish the role-specific multi-target/different-tweak assumptions; a secret PRF premise cannot close this row. |
| Message-compression family | `hmsg`: exact R/seed/root/message concatenation, 34-/49-byte deployed outputs | Concrete bytes, widths and XOF prefix consistency are checked/proved. ITSR/full-output transfer with public-key and randomizer dependencies remains open. |
| Address/message encoding | Full 32-byte address; canonical DSM wrapper bytes | Existing address/binding theorems apply. Mapping to external abstract coordinates and standard compressed addressing still needs a checked injection. This comparison is at internal signing functions; standard external SLH-DSA message/context framing is not silently adopted. |

`seedDistinguisher` is executable and receives expanded bytes, not the master
seed. It computes the existing key-generation suffix, runs the existing adaptive
query strategy, answers using unchanged `sign`, and applies the same freshness
and `verify` predicates. `seed_distinguisher_exact` and
`seed_hybrid_real_equivalence` prove the connection to the original game.
`uniformExpansion` is proved bijective onto all 3n-byte strings; it is explicitly
the ideal destination. Field/key widths and the signing-attempt budget are proved.

`seed_prg_hybrid_bound` uses an exact cross-multiplied probability inequality:
actual forgery probability is at most uniform-expansion forgery probability plus
the real/ideal distinguishing advantage of this constructed distinguisher. The
different sample-space cardinalities are preserved. No event-extraction premise,
independent deployed seed sampling or small-advantage axiom was inserted.

Controls exercise correlated nonzero expansion, adaptive signing, freshness,
positive forgery under an intentionally insecure oracle, and unequal-denominator
accounting. They do not assert a vulnerability of BLAKE3. This is the first
explicit model-level hybrid reduction, not the complete computational-security
theorem; primitive budgets, efficient strategies and remaining rows are open.
