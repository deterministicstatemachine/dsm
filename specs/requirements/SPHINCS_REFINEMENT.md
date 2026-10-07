# DSM SPHINCS construction v2: verification and refinement evidence

## Claim and baseline

This program starts from Rust at `2251f98d5` (parent of the verification changes),
including the construction-v2 change `229409135` (#1100). It supplies an executable
Lean 4.23.0 model of the implemented construction, kernel-checked structural
lemmas, and ordered primitive-transcript comparisons with Rust. **It does not
prove compiled Rust correctness, EUF-CMA security, or FIPS 205 compliance.**

Authority: `AGENTS.md`, `.github/instructions/rules.instructions.md`,
`specs/README.md`, the four current specifications, and their master requirements,
gaps and verification matrix. The former whitepaper/dBTC instruction files and
`.Codex/traces/memory.md` do not exist in this checkout. Current repository
specifications replace historical skill architecture notes. This is evidence for
MR-DSM-0259 and the canonical-encoding/binding obligations; it does not upgrade
those requirements to an unconditional cryptographic security claim.

Production algorithms, message bytes, key sizes and acceptance rules are preserved.
Production changes add typed failure reasons, guarded KDF/signing working buffers,
seed diagnostic redaction and the documented JNI boundary hardening.
Recording, export and wrapper comparison code is compiled only under `cfg(test)`.
No existing path is replaced, so no legacy path is removed. The original checkout's
unrelated `crates/dsm-android-anchor/Cargo.lock` change is outside this branch.

## Actual construction and parameter inventory

| Variant | n | h | d | h' | a | k | WOTS len | PK | SK | signature | H_msg |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| SPX128s | 16 | 63 | 7 | 9 | 12 | 14 | 35 | 32 | 64 | 7856 | 30 |
| SPX128f | 16 | 66 | 22 | 3 | 6 | 33 | 35 | 32 | 64 | 17088 | 34 |
| SPX192s | 24 | 63 | 7 | 9 | 14 | 17 | 51 | 48 | 96 | 16224 | 39 |
| SPX192f | 24 | 66 | 22 | 3 | 8 | 33 | 51 | 48 | 96 | 35664 | 42 |
| SPX256s | 32 | 64 | 8 | 8 | 14 | 22 | 67 | 64 | 128 | 29792 | 47 |
| SPX256f | 32 | 68 | 17 | 4 | 9 | 35 | 67 | 64 | 128 | 49856 | 49 |

All six are supported by the crate. Device AKs, ordinary host signatures and
per-step EKs use **SPX256f**. Partition signatures use **SPX128f** at the imported
anchor dependency boundary. Other variants remain supported APIs, rather than
being presumed deployed. Size-only variant discrimination is not a suite tag.

Keys: `pk = PK.seed || PK.root`; `sk = SK.seed || SK.prf || PK.seed || PK.root`.
Signatures: `R || k*(SK_FORS || a authentication nodes) ||
d*(len WOTS elements || h' authentication nodes)`. Fields are fixed-length raw
bytes; no outer variant or construction-version byte exists in this format.
Empty messages are errors; wrong verification key/signature lengths return false;
wrong signing key lengths are errors. Higher `SignatureKeyPair` wrappers also
refuse empty key/signature inputs, so their error behavior is not identical to the
primitive. No malformed-content theorem says every wrong byte string must reject:
valid signatures are byte strings of the same size. Rejection beyond shape is the
computed-root check plus cryptographic assumptions.

## Customization versus the standard

The parameter geometry and algorithm structure are modeled after FIPS 205
Algorithms 2–20, but **this is a DSM-specific BLAKE3 construction**, not a
standardized SHA-2/SHAKE SLH-DSA suite. Standard vectors cannot validate it.
Reference: [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).

For the implemented n-byte outputs:

* `PRF = keyed-BLAKE3(derive_key("DSM/sphincs/v2/prf", SK.seed), PK.seed || ADRS)[0:n]`.
* `F/H/T_l = keyed-BLAKE3(derive_key("DSM/sphincs/v2/thash", PK.seed), ADRS || M)[0:n]`.
* `PRF_msg = keyed-BLAKE3(derive_key("DSM/sphincs/v2/prf-msg", SK.prf), PK.seed || message)[0:n]`.
* `H_msg = BLAKE3 derive-key-mode XOF("DSM/sphincs/v2/h-msg", R || PK.seed || PK.root || message)`.
* A 32-byte input seed initializes `rand_chacha::ChaCha20Rng`, expanding exactly
  `3*n` bytes; the top XMSS root is computed and appended. OS entropy acquisition
  is in the host wrapper. Deterministic signing uses `opt_rand = PK.seed`.
* There is no standard external message/context framing. DSM-specific callers
  provide the exact bytes to sign. The host wrapper adds no domain or prehash.
* Signing checks the reconstructed hypertree root before returning the signature.
* ADRS is eight big-endian u32 words. Its high tree word is zero; DSM uses a u64
  tree index. Changing type clears the keypair/chain/hash words. Types 0–6 separate
  WOTS hashing/compression, XMSS, FORS tree/roots, WOTS PRF and FORS PRF.

KDF context strings are BLAKE3 contexts without NUL suffixes. DSM ordinary domain
hashing instead absorbs `tag || 0x00 || payload`; these are distinct constructions.
Do not substitute one for the other. Construction v1 is retired; this model is
v2 only. Bare key/signature sizes do not prove universal rejection of v1 artifacts.

## DSM wrappers and paths actually inspected

Exact line references and file identities are generated in
`SPHINCS_REFINEMENT_MAP.tsv`; `SPHINCS_CALLERS.tsv` lists lexical references,
including tests. Neither a lexical list nor a source hash proves runtime reachability.
The map fails CI when its source evidence becomes stale.

* `crypto/sphincs.rs`: OS-seeded keygen, deterministic keygen, sign, verify, and
  SPX256f convenience wrappers; errors map to `DsmError`.
* `crypto/signatures.rs`: `SignatureKeyPair`, raw forwarding, explicit parameter
  APIs, entropy normalization. These wrappers do not automatically bind a domain.
* `crypto/ephemeral_key.rs`: EK seed is keyed BLAKE3 with Smaster over
  `DSM/ek/v1\0 || alg_id || chain_id || h_n || C_pre || k_step`, **not HKDF**.
  The four trailing fields are 32 bytes; deployed `alg_id` is `SPX256f`.
  The prior AK/EK signs `H(DSM/ek-cert\0 || next_pk || parent_tip)`.
* `core/identity/genesis_v2.rs`: device seed binds wallet/G/device slot; AK seed
  additionally binds authority policy; `SignatureKeyPair::generate_from_entropy`
  supplies the seed normalization: `H(DSM/sphincs-seed\0 || AK_seed)` before
  the crate's ChaCha expansion. This extra hashing step is absent from direct EK
  `generate_keypair_from_seed` calls. `DevID = H(DSM/devid\0 || AK_pk || AttA)`.
  Smaster is a separate KDF binding s0, G, DevID and authority policy. Authorship
  seed material is not by itself an anti-clone guarantee.
* `bilateral/identity_binding.rs`: AK signs
  `H(DSM/kyber-identity-binding\0 || DevID || genesis || Kyber_pk)`; verifies
  required fields and ML-KEM-768 key width before SPX256f verification.
* `sofi/derive.rs`, `sofi/signature.rs`: distinct setup, precommit and fulfillment
  signing domains over their CCB bodies; algorithm/key widths are checked by the
  signature layer. Resolution claim signing additionally binds `u16be(alg)`,
  `u32be(key length)`, the key and AttA; recognition checks key/AttA-derived DevID.
* `economic/claim.rs`, `claim_envelope.rs`: canonical root claim signing and
  authority evidence. `economic/successor_evidence.rs` binds substrate/operation
  evidence. `types/operations.rs` has operation-specific signing bytes;
  `types/receipt_types.rs` contains receipt/session/finalization targets.
* DLV, admission, recovery and external dBTC execution call sites appear in the
  inventory. Their object codecs and authorization are not silently covered by a
  SPHINCS primitive proof. Hardware/recovery are recorded dependency boundaries.
* Android: WebView MessagePort → Kotlin bridge/`UnifiedNativeApi` →
  `Java_com_dsm_wallet_bridge_UnifiedNativeApi_processEnvelopeV3` → JNI
  byte-array conversion / `process_envelope_v3` → ingress/router → SDK handler
  → Core canonical target / signing wrapper → `dsm_sphincs`. BLE identity ingress
  has additional transport entries. There is no direct SPHINCS C ABI in this crate.
  JNI uses `extern "system"`, platform array allocation, unsafe environment
  recovery and unwind/error translation; those are outside these proofs.

## Formal model and kernel-checked results

`lean4/Sphincs/Model.lean` is executable over a parameterized primitive oracle.
It models all six parameter sets, byte encoding and parsing, addresses, base_2b,
WOTS checksum/chains/signing/public-key reconstruction, XMSS nodes/authentication
paths, FORS signing/reconstruction, hypertree signing/reconstruction, seeded
keygen, deterministic signing with self-check, and verification. It also models
four tested DSM wrapper preimages and the resolution-claim input builder.

`lean4/Sphincs/Proofs.lean` proves:

| Theorems | Scope of the formal claim |
|---|---|
| `be_width`, `be_roundtrip` | big-endian encoding width; decoding recovers any number below `256^width` |
| `parse_encode`, `encode_parse`, `canonical_unique`, `wrong_length_rejected` | canonical fixed-length **raw** key/signature byte objects; not protobuf/CCB object codecs |
| `signature_split_rejoins` | no bytes lost by R/FORS/HT partitioning |
| `type_clears`, `type_preserves_tree`, `address_width` | ADRS type reset, preserved layer/tree, 32-byte output |
| `next_layer_leaf_bounded`, `next_layer_reconstructs`, `digest_*_bounded` | bounded index arithmetic and exact layer decomposition |
| `parameter_layout`, `signature_sizes`, `wots_digit_count`, `checksum_width_three` | supported finite parameter geometry and digit/signature lengths |
| `chain_composes`, `wots_signature_recovers_chain_top` | WOTS signed digit followed by remaining chain steps recovers the same chain top, for any deterministic primitive oracle |
| `verify_empty`, `verify_bad_pk`, `verify_bad_signature`, `accepted_requires_exact_lengths`, `verify_bad_signature_no_hash_calls` | empty error and malformed-width rejection precede hash calls; accepting inputs have exact widths |
| `auth_walk_recovers_tree`, `xmss_authentication_path_recovers_tree`, `fors_authentication_path_recovers_tree`, `fors_orientation` | inductive Merkle path root reconstruction under stated node/parent premises and FORS index orientation |
| `verification_structure` | acceptance iff the concrete FORS → XMSS/WOTS → hypertree reconstruction equals the key root, on correctly sized nonempty inputs |
| `cert_preimage_binding`, `devid_preimage_binding`, `identity_preimage_binding`, `ek_seed_preimage_binding` | typed fixed-width fields cannot be substituted while keeping these exact preimages |
| `changed_cert_fields_same_digest_is_collision` | substituting certificate key/tip with equal digest exhibits a hash collision |

No new `axiom`, `sorry`, `admit`, `opaque` security claim or `native_decide` proof
is introduced. Headline `#print axioms` output contains only Lean logical axioms
`propext`, `Classical.choice` and/or `Quot.sound`, or none. Cryptographic security is not assumed as
an unconditional globally injective finite-output hash. `DSMCryptoBinding.lean`
and `DSMCertChain.lean` previously declared stronger global axioms; on audit-prep
(2026-10-07) they were restated as collision/forgery reductions and declare none
(CONFORMANCE_GAPS.md, "Lean premises"). This work does not depend on them.

### Complete model signer correctness

`lean4/Sphincs/Signer.lean` now proves `wots_sign_correct`,
`xmss_sign_correct`, `fors_sign_correct`, `supported_ht_sign_correct`,
`signer_correct`, `generated_key_valid`, and `keygen_sign_verify`.
For every implemented parameter variant, every 32-byte seed and every nonempty
message, key generation followed by signing produces an exactly sized signature
accepted by verification. These are universal theorems about the concrete model,
including the actual serialized sibling blocks and nested FORS/WOTS/XMSS loops.
The sole primitive premise is `OutputWidths` for a deterministic `Oracle Id`;
no cryptographic hardness premise is required for functional correctness.
For caller-supplied secret keys, `signer_correct` explicitly requires the stored
root to agree with the seed-derived root. This is not an unforgeability theorem.
The recursive hypertree model preserves Rust's primitive call order, including
skipping final-layer public-key reconstruction until the signer's self-check.

### Actual Rust extraction and source proof

Aeneas `aa66752b15d02335f936f607b5ad5b9fecb65b13` and Charon
`c8f15d7d658c86a95658f71ad99cddd4be002e04`, using Rust
`nightly-2026-09-17`, extracted the actual crate's MIR. The signing and verification return types now contain typed failure reasons,
with diagnostic strings generated at the reporting boundary. This removes their
borrowed-string translation failures. The public call graph translates with
`keyed` treated as an explicit BLAKE3 primitive boundary; its nested-slice body
remains unsupported. Standard-library and dependency models still require work.
External axiom templates are excluded from the checked proof graph.

The actual `next_layer` function translates without external axioms. Generated
`Types.lean` and `Funs.lean` and its total correctness/refinement theorem are in
`lean4/Sphincs/RustExtraction/`. `next_layer_refines` connects the extracted
64-bit Rust computation to `DSM.Sphincs.nextLayer`, for every tree and every
height at most nine (covering all six implemented variants), including shift,
subtraction and narrowing-cast behavior. Its toolchain is Lean 4.31.0; the main
model/proof gate remains Lean 4.23.0. Regenerate and check with
`DSM_AENEAS_REPO=... DSM_CHARON_REPO=... bash scripts/check_sphincs_source_refinement.sh`.
The script checks translator revision pins and exact generated-source agreement,
then kernel-checks the proof. Build the pinned translators and Aeneas Lean backend
first. This additional extraction gate is local, not installed in CI.
Charon/MIR extraction and Aeneas translation remain trusted for this source proof;
Rust compiler, LLVM, linked libraries and machine execution are not covered.

### Memory, timing and JNI follow-up

BLAKE3's zeroization feature is enabled. Keyed hash state and final digest,
chain working buffers (including replaced buffers), and the key-generation
working allocation now use `Zeroizing`. The returned secret key retains the
existing `ZeroizeOnDrop` ownership. Rust/Lean transcripts are unchanged.
This does not prove erasure of compiler/register/allocator copies. ChaCha RNG
state, dependency internals, caller-owned seeds and abort behavior remain open.

Miri passes the actual address layout and address-type clearing tests. This is
memory/undefined-behavior checking for those executions only. It does not cover
all signer executions, Android, or foreign JNI handles.
The actual `processEnvelopeV3` JNI entry point converts JVM byte arrays, dispatches
and converts responses under an unwind boundary. Valid raw JNI environment,
thread attachment, reference lifetime and JVM exception semantics remain external
obligations; catching panics does not prove those unsafe contracts.
No timing theorem is claimed: index/chain schedules and root comparison alone do
not establish constant-time BLAKE3, generated machine code, caches or CPU behavior.

### Rust, binary and JNI follow-up

`type_clear_correct` and `tree_set_correct` now prove total execution of the
actual extracted Rust address methods, including every fixed-array update.
The former preserves all other address words and writes type plus three zeros;
the latter writes the zero high tree word, the narrowed upper 32 bits and lower
32 bits. These universal source statements use no hash premise and report only
Lean logical axioms. The pinned source-refinement gate regenerates all three
extracted functions and rejects a changed generated file.

The Android `processEnvelopeV3` entry point now receives the JNI library's
transparent, lifetime-bearing `JNIEnv`, `JClass` and `JByteArray` parameters.
It no longer reconstructs raw input handles with `'static` lifetimes, including
on panic recovery. Byte-array conversion errors and panic recovery preserve a
pending JVM exception, and response-allocation failure returns null without
attempting another allocation. This follows the permitted exception-handling
calls in the [JNI specification](https://docs.oracle.com/en/java/javase/21/docs/specs/jni/design.html#exception_handling).
Kotlin declares this method `@JvmStatic`, so the class parameter matches its
call path. No unsafe block was introduced. JNI validity, JVM implementations,
callbacks, other raw-handle entry points and error helpers remain outside this
proof; typed parameters are not a formal JVM/binary theorem.

`SphincsKeyPair` diagnostics redact the entire secret key, with a test that
checks seed contents are absent from formatting. The public key stays visible.
No cryptographic bytes, domain tags, key derivation or signatures change.

An Android arm64/API-28 release `libdsm_sdk.so` was built using NDK
27.0.12077973, `--locked --features jni,bluetooth`, emitting IR and assembly.
The ELF is AArch64 and exports the exact JNI symbol; its optimized LLVM signature
has three pointer arguments and a pointer result. A binary hash/build manifest is
provided with the review outputs. Build success and ABI inspection do not prove
compiler preservation, ARM instruction semantics, side-channel noninterference
or any whole-binary equivalence theorem. No device execution is claimed.

The current `scripts/extract_sphincs_rust.sh` translates the actual public
key-generation/signing/verification call graph successfully at the explicit
`keyed`/BLAKE3, ChaCha, zeroization and constant-time comparison boundaries.
It produces an inventory of **40 unproved external declarations** (34 functions,
six types), including iterator/Vec helpers and scalar operations missing from
the translator library, not just cryptographic assumptions. The script is an
extractor, not a proof gate, and does not compile or accept external axiom templates.
Full functional source refinement requires concrete models for those interfaces,
proofs that the models agree with their implementations, and simulation theorems
for the generated functions. No universal signer source theorem is claimed.

The next binary/timing theorem must fix the exact executable, compiler/linker,
ARM machine model, linked primitive/JVM contracts and leakage model. It must
prove a simulation from machine execution to the source/spec, plus relational
trace equivalence for secrets with explicitly permitted public outputs. This
work has no such machine semantics or validated compiler theorem. Register,
stack, allocator, dependency and RNG erasure are also not proved by the existing
buffer cleanup. These obligations cannot be discharged by treating compilation,
Miri, branch inspection or transcript equality as universal proofs.

Follow-up validation: all 17 crate tests, the 114 transcript cases and five
mutation controls pass; source proofs pass with warnings as errors; Android
arm64 SDK checking and the release build pass. Crate Clippy, real-code guard,
invariant scan, codegen guard, SPDX and formatting pass. Android SDK Clippy with
`-D warnings` fails: 190 errors versus 191 on the unchanged JNI baseline, with no
added diagnostic categories. The SDK lint gate, on-device exception/lifetime
checks, full source/binary simulation and timing/memory guarantees remain open.

### Parser refill source proof and extraction progress

The checked Rust graph now also includes the actual `base_2b` implementation
and both of its loops. `refill_complete` proves total execution of its inner
refill loop for any width from 1 to 14, any residual bit count at most seven,
any accumulator value and any byte buffer satisfying the exact required-read
bound. This covers all implemented WOTS/FORS widths. The proof gives the exact
zero/one/two-byte read count and a final bit count between `b` and `b+7`.
`refill_read_count_noninterference` proves two executions with arbitrary different
bytes and accumulator values advance their read index and bit count identically,
when their width, initial counters and sufficient-buffer premises agree.
`refill_step` additionally identifies the precise shift/OR accumulator update;
`byte_refill_complete` identifies the loaded byte value for the zero-accumulator
one-byte case. No hash or PRF assumption appears in these source proofs.

This is a memory-bound/termination and read-count theorem for the extracted
inner loop. It is not a full `base_2b` bitstream-equivalence theorem, an outer-loop
buffer-invariant proof, a signer-wide noninterference theorem, a hardware timing
bound or compiled-binary memory proof. Remaining parser obligations are explicit.

The crate's Rust `Error::Crypto` payload is now `CryptoFailure`, with four typed
reasons. This is a Rust source API change; repository callers and transcript tests
were updated. The rejection conditions and existing diagnostic strings are
unchanged; Core uses `why.message()` at its reporting boundary. No signature,
key layout, domain tag, wire error encoding or construction version changed.
The guarded KDF now uses `Zeroizing<blake3::Hasher>` and a guarded digest during
the material phase, addressing another private working-state cleanup gap.
The signer now also guards the randomizer, FORS and hypertree signature components
and its assembled signature until the existing self-check succeeds. Working
copies are cleared on both success and self-check failure; the returned signature
is copied only after acceptance. This adds a successful-path allocation/copy.
Caller-owned material, returned-key copies, RNG state, dependency internals and
machine register/stack erasure remain outside the proved guarantees.

Current validation passes: 18 crate tests, 1,382 Core tests, all 114 transcript
cases and five mutation controls, the expanded pinned Rust proof gate with
warnings as errors, crate/Core Clippy, firmware `thumbv8m.main-none-eabihf`
checking, and a fresh Android arm64 release build. The public graph extraction
succeeds with the declared primitive boundary and lists its unproved externals.
The focused guarded-KDF comparison also passes under Miri; this checks the
executed cases for interpreter-detected undefined behavior, not universal memory
safety or erasure.
A custom Miri sysroot experiment failed to link native build scripts; it is not
used by either checked gate. Android SDK Clippy's existing failure remains open;
on-device exception handling, whole signer/binary equivalence and general
constant-time/memory/JNI guarantees are still not certified.

### New security game and artifact-lock projects

`SPHINCS_SECURITY_CHARTER.md` freezes the initial classical single-key EUF-CMA
scope for deployed SPX128f/SPX256f, symbolic signing-attempt/message limits,
deterministic signing and a uniform 32-byte master seed. It records the PRG
expansion, public thash key, correlated EK/multi-key and quantum boundaries.
The current `SecurityGames.lean` Strategy is extensional and unbounded; an
adversary runtime/primitive-query cost model is still required for a computational
security theorem. No numerical or post-quantum advantage bound is asserted.

The executable game calls the existing `generateKeypair`, `sign` and `verify`
model definitions with an explicit deterministic Oracle Id parameter. A separate
concrete BLAKE3 evaluator is now available; the game has not yet been universally
specialized to it, and ChaCha remains abstract. The transcript and extraction boundaries
continue to apply. The adversary's finite random tape is sampled independently
of the uniform master seed. Kernel-checked results establish master-seed sampler
bijectivity, legal-query rejection, the attempt budget, public-key preservation,
repeated-query replies, queried-message exclusion and finite-event union bounds.
Probabilities are exact numerator/positive-denominator pairs with a rational
view; union bounds use the shared denominator. These are game/accounting proofs,
not PRF/XOF replacement, bad-event classification or forgery extraction.
No security assumption or external axiom template was imported.

Executable controls check adaptive queries, invalid/oversized messages, freshness,
budget exhaustion and exact event accounting. A deliberately insecure zero-output
oracle satisfies the requested output widths yet permits a fresh SPX128f forgery.
This negative control prevents equating honest signer correctness/output widths
with security; it is not a counterexample to actual BLAKE3. The CI refinement gate
now compiles the games and runs these controls.

`scripts/lock_sphincs_artifact.py` (Python 3.11+) records and rechecks the fixed
Android arm64/API-28 SDK's build inputs and emitted artifacts, exact SDK compiler
invocation, compiler/LLVM/NDK/linker tools, dependency archives, generated inputs,
Cargo.lock, effective CPU/features and build-time Android link interfaces.
A verbose fresh build supplies the compiler command. This is local artifact
identity evidence, not source-to-IR or machine simulation. Runtime libc/JVM/OS,
allocator state, signals, scheduling and the microarchitecture remain unlocked.
No supported ARM machine/leakage/erasure semantics or compiler-preservation
proof exists. The initial closed-kernel theorem therefore remains open even
though the larger SDK candidate has a locked inventory of 1,199 build files.
The inventory check passed; altered artifact, altered inventory and missing
artifact controls were rejected. Lean games/control checks, the full existing
114-case/five-mutation refinement gate, the verbose Android release build,
invariant scan, codegen guard, SPDX and diff checks passed for this follow-up.
Runtime Rust/JNI behavior was not changed. Existing Android SDK lint failures
and absent device/runtime proof checks remain as documented above.

### Certificate extraction and complete parser termination proofs

`WrapperReduction.lean` implements an extractor from a fresh accepted signed
object and its signing-query transcript. It searches for a previously queried
object with the same digest. With a match it returns two different canonical
preimages with equal hash outputs; without a match it returns the accepted
signature on a digest absent from the primitive signing-query list. The
classification is proved, not assumed. The concrete Certificate instance uses
64-byte keys, 32-byte parent tips and DSM/ek-cert framing (108 preimage bytes),
with the existing SPHINCS model verifier. It corresponds to the deployed default
SPX256f certificate format; it is not a stateful authorization/replay theorem.

The instrumented extractor refines the uninstrumented function and provably
issues at most q+1 hash queries for q queried objects. Its exact finite-space
bound is P(wrapper success) <= P(extracted fresh-signature break) +
P(extracted hash collision), with equal denominators. It does not assume hash
injectivity, independent BLAKE3 families or a primitive security bound. This is
a transcript-level reduction: whole adaptive-oracle simulation, adversary time
and memory accounting, primitive replacements, and the underlying SPHINCS
EUF-CMA reduction remain open. Executable controls cover both extraction
branches, exact hash-query inputs and queried-object rejection.

`base_2b_complete` now proves total execution and exact output length for the
actual extracted Rust function, including both loops and its initial mask
construction, for every width 1..14 and b*count <= 8*input.length. The outer-loop
induction preserves the exact bit budget, input bounds and vector-length bound;
each iteration consumes exactly its refill read count and retains at most seven
bits. The source model includes bounded words, casts, slices and Vec operations.
No cryptographic or external-template axiom is used. This closes parser
termination/length and modeled index/arithmetic safety, not digit equality with
the MSB-first specification. Real allocation/OOM, compiler/machine memory and
signer-wide or hardware leakage/erasure/JNI guarantees remain open. The pinned
source gate recompiles these proofs from the unchanged current Rust extraction.

## Executable evidence and reproducibility

Run `bash scripts/check_sphincs_refinement.sh` from the repository root. The CI
Lean job runs it after the existing 18-module gate. The gate, real-code baseline,
and security invariants are not weakened. Toolchain: `lean4/lean-toolchain`;
Cargo dependencies are locked. Generated test data goes under ignored `target/`.

The synthetic seed is `[0xD5;32]`, message is `DSM SPHINCS+ construction vector`.
For **both deployed variants**, the program compares the full keygen/sign/verify
control flow with Rust, every primitive request (mode, context, key, concatenated
input, output width), exact PK/SK/signature outputs, malformed lengths, empty
message, and a damaged signature. Every request must match in order and the
transcript must be completely consumed. It is not just a Rust sign/verify round trip.

There are also **96 deterministic utility cases**, 16 per supported variant,
using ChaCha seed `[45;32]`, plus zero/max digest boundaries. Lean's independent
bit-selection base_2b is compared with Rust's accumulator algorithm, together
with WOTS digits/checksum, digest masks, next-layer indices, parameter layouts
and randomized address words. Four real host wrapper helpers are compared with
Lean's preimage builders and separately recomputed BLAKE3 digests.

Mutation controls must reject changed result, wrong hash mode, changed primitive
input, truncation and trailing data. Generated transcripts contain **synthetic
secret material**; do not enable capture for production keys or upload live-key
traces. They are test artifacts, not DSM protocol wire objects.

The original replay checker validates algorithmic control flow and construction
requests conditional on recorded primitive outputs. A second checker now
independently recomputes every BLAKE3 output using `Blake3.lean`; only ChaCha
expansion remains replayed. The concrete model passes the 35 official vector
lengths in all three BLAKE3 modes, including 131-byte XOF outputs. It matches
517,251 BLAKE3 requests across all 114 DSM transcripts. Altered output bytes and
unknown modes are rejected by independent recomputation controls.

`Blake3Proofs.lean` proves exact output length for root expansion and every
accepted request, and XOF prefix consistency for any two ordered lengths.
`Blake3.lean` proves the request-to-definition wiring, equal 32-byte derive/XOF
results, distinct context strings and the deployed 34-/49-byte H_msg lengths.
These are functional model theorems, with no cryptographic axioms. Compression
and tree equivalence to an independent formal specification, defaulted-access
shape safety, universal Rust equivalence and security reductions remain open.
Pinned primary sources and the per-function cross-reference are in
`SPHINCS_EXTERNAL_PROOF_ARTIFACTS.md`. The paper's <=32-byte output bound does not
directly apply to the deployed message XOFs.

## Narrow SHA-2/BLAKE3 substitution and seed hybrid

`SPHINCS_EXTERNAL_PROOF_ARTIFACTS.md` compares the actual primitive roles to
FIPS 205's SHA-256/SHA-512 constructions and pins five transfer boundaries.
The comparison preserves DSM's algorithm; it does not replace BLAKE3 with SHA.

`SeedHybrid.lean` implements the first explicit challenge reduction. It proves
the existing `generateKeypair` is expansion followed by the unchanged root/key
computation. A distinguisher given only expanded bytes reproduces the adaptive
signing/forgery game exactly. The destination sampler covers all 3n-byte strings
bijectively; field/key widths and signing-attempt bounds are checked. The exact
cross-multiplied probability theorem bounds actual success by ideal-expansion
success plus this distinguisher's PRG advantage, preserving different space
cardinalities. No small-advantage premise or independent deployed seed draw is
introduced. Efficient runtime/memory/primitive-query costs, actual ChaCha20 PRG
hardness and the remaining BLAKE3 family reductions remain open.

## Remaining trusted computing base and review obligations

1. Lean kernel, core library, toolchain and logical axioms; executable-checker
   compiler/runtime and the host OS are additionally trusted for test evidence.
2. Correctness and security of BLAKE3 derive-key/keyed/XOF modes and truncation;
   hash/PRF assumptions appropriate to the **custom** multi-key construction,
   domain/address separation, robustness to deterministic R and quantum attacks.
   No complete SPHINCS security reduction or numerical forgery bound is proved here.
3. ChaCha expansion and seed entropy/uniqueness; OS RNG, wallet entropy
   normalization, KDF inputs, master/AK/EK ownership, secret storage and erasure.
4. Rust-to-Lean correspondence outside the extracted layer/address/refill proofs is a
   manually reviewed map plus tested transcripts, not a universal simulation theorem. Unsupported
   shape/content combinations and the four undeployed variants' full sign/verify
   executions have no transcript coverage in this program.
5. Constant-time behavior, branches on public indices, allocation, cache/CPU side
   channels, fault resistance, secret copies, zeroization and memory lifetime.
   `ct_eq` is not a proof of constant-time compiled execution or fault security.
6. Rust/LLVM optimizations, BLAKE3 assembly/SIMD, dependency supply chain, release
   overflow behavior, no_std/firmware target behavior, ABI, JNI, Kotlin, WebView,
   transport framing, platform byte arrays and error handling. Host test transcripts
   do not certify Android or firmware binaries.
7. Full Rust array/slice safety and Rust WOTS/FORS/XMSS/HT source correctness,
   all operation/receipt/SoFi/CCB codecs, replay/frontier checks and device authority
   admission need their own refinement proofs and negative tests.
8. Deterministic signing is not proof that only one signature can verify for a
   body. MR-SOFI-0111's uniqueness wording must not be inferred from this program;
   public verification cannot in general recompute deterministic R from SK.prf.

Human review should prioritize the custom primitive instantiation and its security
reduction, secret handling/timing, wrapper domain/key attribution, and the binary
boundaries. These artifacts make the exact proof/test boundary reviewable; they
are not a substitute for that review.

## Validation performed for this change

The final refinement run passed **114 cases**, matching **517,253 primitive
requests** and all expected outputs/results; all five mutation controls rejected
with their specific expected diagnostic. The source evidence check passed with
96 anchors and 378 lexical caller references.

Also run and inspected in this isolated checkout:

* `cargo test --offline --locked -p dsm-sphincs`: 16 tests passed.
* `cargo test --offline --locked -p dsm --lib`: 1,382 tests passed.
* `cargo test --offline --locked -p dsm --lib crypto::`: 131 tests passed.
* Both `dsm-sphincs --all-targets` and `dsm --lib --tests` Clippy checks with
  `-D warnings`: passed after fixing harness lint errors without suppressions.
* Complete `Signer.lean` model proofs and regenerated extracted Rust `next_layer`
  proof: passed; only Lean logical axioms in the reported dependencies.
* Two focused Miri address tests: passed. These do not certify full signer memory safety.
* All 18 existing Lean modules and the new model, proofs and checker with
  `-DwarningAsError=true`: passed; printed dependencies contain no proof holes.
* Real-code guard for touched Rust scopes, `scripts/ci_scan.sh`,
  `scripts/codegen_enforce.sh`, SPDX check, formatting and `git diff --check`:
  passed. Workflow YAML parsed successfully.
* Diff checks for `proto/`, Android, frontend and language SDK boundaries:
  no changes. No protocol schema or codegen output is added or modified.

Earlier failed attempts (the real-code guard, proof elaboration and harness lint
checks) were corrected and the affected final checks rerun. There are no known
remaining failures in the checks above.

**Unrun checks:** full workspace/SDK/storage integration suites; Android/Gradle
and device deployment; frontend canonical tests and protobuf regeneration;
Go/Swift suites; release-target/firmware binaries; hosted GitHub CI. The source
changes add verification artifacts and explicit working-buffer cleanup rather than new protocol codecs or
bridge behavior; these wider checks are still required before a release or audit
claim extending to those platforms. Local CI wiring has been inspected and its
refinement command run, but no hosted job is claimed to have executed.
