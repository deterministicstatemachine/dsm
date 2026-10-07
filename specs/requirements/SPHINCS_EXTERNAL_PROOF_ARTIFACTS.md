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
