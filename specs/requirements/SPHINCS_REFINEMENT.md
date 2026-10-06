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
The only production refactor is a forwarding helper around the same BLAKE3 KDF.
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
an unconditional globally injective finite-output hash. The existing
`DSMCryptoBinding.lean` and `DSMCertChain.lean` have stronger global assumptions;
this work neither depends on them nor presents their assumptions as discharged.

**Universal signer correctness is not yet proved.** The general inductive
authentication-path theorem is proved under explicit parent-recurrence and sibling
node premises, including FORS orientation arithmetic. The parent recurrences are
now discharged against `xmssNode` and `forsNode` in `xmss_signer_tree_path` and
`fors_signer_tree_path`. The complete serialized sibling/leaf correspondence and
whole WOTS/FORS/hypertree signer composition still remain to be discharged. The executable FORS/XMSS/hypertree
algorithms and acceptance equation are present; their agreement with Rust is
currently established on the generated cases below, not for every possible input.
The complete CCB/operation/JNI wrapper refinement also remains open.

### Additional signer obligations discharged

`base2b_digit_bound` proves every generated digit is below `2^b` for all inputs;
`wots_digit_bound` specializes this to 0–15, including the checksum digits.
`wots_generated_digit_recovers` therefore discharges the digit-range premise of
WOTS chain recovery for the actual `wotsDigits` function.
`xor_one_is_sibling` proves the signer's XOR sibling selection equals the path
verifier's parity selection for every natural index. `fixed_block_slice` proves
an exact-width concatenated block is recovered at its serialized offset.
`thash_width`, `prf_width`, `chain_width`, `wots_pkgen_width`,
`xmss_node_width`, and `fors_node_width` explicitly require
`OutputWidths`: primitives return the requested byte count. This is an interface
contract, not collision resistance or PRF security. Parent recurrence theorems and
signer tree path theorems require no hash-security assumption. The path theorems
still require sibling-byte correspondence; they are not complete signer proofs.

For source refinement, [Aeneas](https://github.com/AeneasVerif/aeneas) supplies a
Rust-to-Lean translation pipeline for a supported safe-Rust subset. Its
[cryptographic verification documentation](https://github.com/AeneasVerif/aeneas/blob/main/documentation/crypto-verification.md)
describes proving translated implementations against mathematical specifications.
Neither `aeneas` nor `charon` is installed in this environment. No extracted DSM
crate, translated semantics, or extraction compatibility result has been produced.
Installing a translator alone would not discharge the simulation theorem, BLAKE3
primitive contracts, or compiled-binary/JNI refinement. These are still explicit
open obligations, not claims made on the strength of the manual source map.

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

The primitive **outputs** in a transcript are trusted Rust BLAKE3/ChaCha results,
not Lean implementations of those primitives. Thus the check validates algorithmic
control flow and construction requests **conditional on those results**. It does
not independently test BLAKE3 compression, ChaCha, or their security.

## Remaining trusted computing base and review obligations

1. Lean kernel, core library, toolchain and logical axioms; executable-checker
   compiler/runtime and the host OS are additionally trusted for test evidence.
2. Correctness and security of BLAKE3 derive-key/keyed/XOF modes and truncation;
   hash/PRF assumptions appropriate to the **custom** multi-key construction,
   domain/address separation, robustness to deterministic R and quantum attacks.
   No security reduction or numerical forgery bound is proved here.
3. ChaCha expansion and seed entropy/uniqueness; OS RNG, wallet entropy
   normalization, KDF inputs, master/AK/EK ownership, secret storage and erasure.
4. Rust-to-Lean correspondence is a manually reviewed map plus tested transcripts,
   not a universal simulation theorem or a validated source translator. Unsupported
   shape/content combinations and the four undeployed variants' full sign/verify
   executions have no transcript coverage in this program.
5. Constant-time behavior, branches on public indices, allocation, cache/CPU side
   channels, fault resistance, secret copies, zeroization and memory lifetime.
   `ct_eq` is not a proof of constant-time compiled execution or fault security.
6. Rust/LLVM optimizations, BLAKE3 assembly/SIMD, dependency supply chain, release
   overflow behavior, no_std/firmware target behavior, ABI, JNI, Kotlin, WebView,
   transport framing, platform byte arrays and error handling. Host test transcripts
   do not certify Android or firmware binaries.
7. Full Rust array/slice safety, universal WOTS/FORS/XMSS/HT signer correctness,
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
changes introduce verification/test artifacts rather than new protocol codecs or
bridge behavior; these wider checks are still required before a release or audit
claim extending to those platforms. Local CI wiring has been inspected and its
refinement command run, but no hosted job is claimed to have executed.
