# DSM construction-v2 security and binary proof charter

Status: proof target frozen for the initial projects. Computational target:
the classical reduction of EUF-CMA to explicit primitive events and
distinguisher advantages is proved (`euf_cma_reduction`, audit-prep
2026-10-07; see SPHINCS_REFINEMENT.md), as is the challenger's primitive-request
budget (`challenger_request_budget`); the primitive assumptions themselves, an
adversary cost model, numerical bounds and the quantum target are not. Binary
target: not achieved.
Authority: the current four DSM specifications, MR-DSM-0259, and the owner's
explicit request for new computational-security and pinned-binary proof projects.
This charter defines analysis scope, not a change to protocol acceptance.

## Computational target

Start with single-key, classical EUF-CMA for deployed SPX128f and SPX256f.
All six variants retain their functional-correctness results. Signing attempts
are bounded by the symbolic natural number q_s; legal messages have length
1..L for a symbolic positive L. Repeated messages count against q_s. A valid
forgery must contain a legal message never submitted as a legal signing query.
The adversary sees PK and query replies, chooses queries adaptively and has
public verification access through local computation. There is no separate
stateful verification oracle or secret-key export. The initial extensional
Strategy interface has no runtime or primitive-query cost model. A computational
security bound must introduce explicit adversary time/memory and primitive-query
budgets; it cannot quantify over unrestricted Strategy functions as efficient
adversaries. The reduction's own overhead is bounded: the challenger issues at
most keygenCost + q_s·signCost + verifyCost primitive requests (`QueryCost.lean`).
The adversary's time/memory/query budget remains open. This is EUF-CMA, not strong
unforgeability: a different signature on an already queried message does not win.
Invalid-message queries return no signature and consume an attempt. Exhaustion
fails the game. These are experimental query-budget rules, not runtime changes.

Sample exactly one uniform 32-byte master seed, then use the actual deterministic
ChaCha20Rng expansion and key generation. Do not replace its 3n-byte expansion
with three independent uniform n-byte seeds without a separate PRG hybrid and
advantage term. In particular, SPX256f's 96 expansion bytes carry at most the
master seed's 256 bits of entropy. DSM EK derivation supplies correlated seeds;
that distribution and multi-key exposure are covered by the multi-key game
(`MultiKey.lean`, `multi_key_reduction`, audit-prep 2026-10-07): for any joint
distribution of seeds, a forgery under any key is one of that key's four
primitive events.
Production seed sources are outside the uniform-master-seed experiment.

Signing uses the implemented deterministic R: derive-key context
DSM/sphincs/v2/prf-msg on SK.prf, then keyed BLAKE3 on PK.seed || M, truncated
to n bytes. There is no independently sampled opt_rand; PK.seed is public/fixed.
Repeat-query behavior must retain this determinism. No uniqueness claim follows.

The first game uses the existing executable Model.generateKeypair/sign/verify
and explicit primitive requests. Candidate hybrids must distinguish PRF,
PRF_msg, H_msg, F, H, T_l, seed expansion, EK derivation and wrapper hashes.
F/H/T_l share the actual thash context and derived key; their address kinds and
input lengths must justify any separation. PK.seed and its thash-derived key are
public. A secret-key PRF assumption alone cannot justify replacing thash calls.
Distinct strings or typed request labels do not establish independent oracles.
Use concrete primitive distinguishing assumptions with explicit reductions;
ideal-primitive games are intermediate models, not claims about actual BLAKE3.
No primitive advantage, quantum bound, signing-query security limit or numerical
security level is assigned before the reductions exist.

The initial classical executable game and finite probability accounting do not
model superposition queries. A quantum EUF-CMA/QROM target, with classical signing
queries and explicitly specified quantum primitive access, is an independent
open obligation. Classical lemmas may be reused only when their premises hold.

Wrapper targets retain their exact existing canonical bytes: EK derivation and
certificates, DevID, Kyber identity binding and SoFi resolution claims, then
setup/precommit/fulfillment, claim/successor authorization and replay/frontier
semantics. The current primitive game signs raw bytes; it does not claim any of
these wrapper authorization theorems. Each needs canonical-object injectivity
(or specified equivalence), collision reduction and its stateful acceptance model.

## Binary target

First close the cryptographic source kernel; do not broaden its proof to JNI.
The initial artifact candidate is the existing Android arm64/API-28 release SDK
built at dc3323cd3ac94470822c1bc7e405e77f156c7790. An artifact manifest must lock
its complete reachable source/build inputs, compiler and target, Cargo.lock,
features, effective optimization/panic/LTO/overflow settings, NDK/linker tools,
linked dependencies, generated sources and binary/IR/assembly hashes.
The full SDK candidate includes JNI and is build evidence only; the initial
functional theorem covers the kernel only after a closed source semantics and
validated compiler/machine simulation exist. No verified-compiler substitution
is permitted to claim equivalence of the existing Rust/LLVM binary.

Leakage and erasure are separate targets. Proposed leakage observations include
branches, memory addresses, instructions, calls and allocations, with explicit
public message/query lengths and released signatures; no ARM microarchitectural
timing theorem is implied by equal source read counts. Erasure must cover live
and freed memory, scalar/vector registers, spills, unwinding/failure paths and
foreign retention. JNI must model handle ownership, thread attachment, pending
exceptions, array allocation/copy and callbacks. These semantics are not supplied
by the artifact manifest or the finite classical game.

## Acceptance of evidence

Kernel-checked theorems must identify their premises and audit their axioms.
No external template axiom may be imported to manufacture a completed reduction.
Event accounting bounds are not a forgery extraction theorem. Artifact identity
is not semantic preservation. Tests and build/ABI observations remain labeled as
such. Update SPHINCS_REFINEMENT.md, CONFORMANCE_GAPS.md and VERIFICATION_MATRIX.md
as the actual proof frontier advances; preserve their open requirements.

Primary research boundaries: the BLAKE3 mode description is an expired
[informational Internet-Draft](https://www.ietf.org/archive/id/draft-aumasson-blake3-00.html),
not a DSM reduction. The [2026 SLH-DSA analysis](https://eprint.iacr.org/2026/632)
is about the standardized construction; transfer to DSM's custom instantiation
must be proved. [CompCert's semantic-preservation guarantee](https://compcert.org/man/manual001.html)
concerns supported C programs and its pipeline, not the current Rust/LLVM/NDK artifact.
