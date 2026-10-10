# Published papers: claims against the current proof boundary

Status: audit-prep, 2026-10-07. This record reconciles the published papers with
the machine-checked artifacts in this repository. Each entry gives the published
wording, what the artifacts actually support, and the replacement wording to
carry into the next revision. Machine-checked links are in `CLAIM_TRACE.tsv`
(checked by `scripts/check_claim_trace.py`). Where a paper and this record
disagree, this record states the supported claim.

The editable sources of both papers below were not available when this record
was written: the newest local source of 2025/592 predates the published
revision (July 11, 2026 build), and no source of the December 2025 Concise
Specification was found. The replacement text is written so it can be applied
to those sources verbatim.

## 1. Deterministic State Machines as Guarded Linear Constraint Systems (IACR ePrint 2025/592, revision of July 2026)

The published revision makes no claim stronger than the artifacts. Its
Assumptions 1 to 4 are stated as assumptions, and its Lean claim ("the
uniqueness and Tripwire core depending on no axioms") remains true. The
artifacts now support a stronger and more precise statement, which the next
revision should use.

**Appendix A, Lean 4 Development: add after "...the absence check before each accepted step."**

> The Lean development declares no axioms. Every theorem rests only on Lean's
> core logic, as recorded per theorem in the kernel's axiom ledger
> (`specs/requirements/LEAN_AXIOM_LEDGER.tsv`). Assumption 3 is proved for the
> model's canonical encoding (`canonical_encode_injective`). Assumption 1 enters
> only as an explicit collision disjunct: equal candidate digests name the same
> state or exhibit a collision of the digest function
> (`candidate_digest_binds_or_collides`). Cryptographic assumptions are never
> introduced as unconditional injectivity of a hash or uniqueness of a
> signature.

**Section 32.1, Machine Checked Scope: add as the paragraph's last sentence.**

> No artifact assumes a hash is injective or that a signature verifies at most
> one message; where a theorem depends on Assumption 1 or 2, its conclusion is
> the reduction itself (an explicit collision or forgery), and
> `specs/requirements/CLAIM_TRACE.tsv` maps each claim of this paper to the
> theorem that states it.

## 2. Deterministic State Machine: A Concise, Post-Quantum Specification (December 2025)

**C12. Abstract, "All algorithms are post-quantum secure and admit efficient verification on resource-constrained devices."**
No theorem supports a blanket post-quantum security claim, and the artifacts
assign no security level. Replace with:

> All primitives are chosen for post-quantum security: BLAKE3 for hashing,
> SPHINCS+ instantiated with BLAKE3 for signatures, and Kyber for key
> encapsulation. Every safety property reduces to collision resistance of the
> hash and unforgeability of the signature; whether these instantiations meet
> those assumptions against quantum adversaries is a property of the
> primitives, and the proof obligations that remain for DSM's BLAKE3
> instantiation are stated in the repository. All verification is efficient on
> resource-constrained devices.

**C13. Section 11.1, "Parameter set: SPHINCS+ BLAKE3, level = NIST Category 5, variant = 'f' (fast)."**
NIST categories are assigned to standardized parameter sets. DSM's BLAKE3
instantiation is not one, and the published SPHINCS+ security proofs do not
transfer to it automatically (`SPHINCS_BLAKE3_ROLE_MAP.md`). Replace with:

> Parameter set: SPHINCS+ with the dimensions of SLH-DSA-256f (n = 32, fast
> variant), instantiated with BLAKE3 for every hash, PRF and tweakable-hash
> role (not SHAKE or SHA-2). The dimensions are those NIST assigns to
> Category 5 for the standardized instantiations; DSM's BLAKE3 instantiation
> is not a standardized parameter set, and no security level is claimed for it
> until the reductions listed in the repository's role map exist.

**Section 11 introduction, "Second-preimage resistance of chained commitments prevents forks; SPHINCS+ ensures non-repudiation."**
Forks are excluded by the acceptance predicate (Tripwire), not by a hash
property; the hash property is what a fork would have to break. Replace with:

> A fork of a chained commitment requires a hash collision or second preimage,
> or a signature forgery; SPHINCS+ signatures bind each step to its signer.

**Section 11.1, Ephemeral certification.** No change to the construction. The
property it relies on is now stated as a reduction (`CLAIM_TRACE.tsv` C06,
C07): a certificate honestly issued for one ephemeral key that also verifies for
another is a hash collision or an EUF-CMA forgery.

## 3. Other papers checked

- *Software Authority, Hardware Identity* (July 2026): its Tripwire assumption
  is already stated as "collision, signature forgery, or a violated predicate".
  No change.
- *Statelessness Reframed* (December 2025): Theorem 4.2 is already stated as a
  reduction to EUF-CMA and collision resistance. No change.
