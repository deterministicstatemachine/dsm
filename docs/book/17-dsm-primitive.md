# Chapter 17 -- DSM Primitive

This chapter defines the primitive boundary in handbook form. The long-form paper lives at
[`docs/papers/dsm_primitive.pdf`](../papers/dsm_primitive.pdf).

## The Primitive

DSM's primitive is the deterministic acceptance system for relationship-local state transitions.
At the smallest useful boundary, it consists of:

- genesis binding and device identity
- the Device Tree and Per-Device SMT
- canonical commit bytes and domain-separated hashing
- stitched receipts with inclusion proofs and signatures
- hash adjacency and Tripwire fork exclusion

If those pieces verify, the transition is valid. If they do not verify, no transport path, storage
node, or UI can make the transition valid.

## What Is Not the Primitive

These are important parts of the overall system, but they are not the primitive itself:

- BLE, NFC, b0x delivery, JNI, and bridge routing
- storage nodes, ByteCommit mirroring, and replica placement
- wallet UI, onboarding flows, and explorer links
- DLVs, CPTA policies, dBTC, DJTE, and recovery workflows

Those systems either carry primitive artifacts, persist them, or compose new semantics on top of
them.

## Why the Boundary Matters

This distinction gives contributors a clean review rule:

- If a change alters acceptance, ordering, proof verification, identity binding, or fork exclusion,
  it is a primitive change.
- If a change alters transport, storage, UX, or operator workflow, it is not a primitive change.

That line matters for threat modeling, code review, and protocol stability.

## Closed by Default

The primitive should be treated as closed, not as an extensible feature surface.

For DSM, this is a design commitment, not a soft preference. The primitive is supposed to be
nailed down early and then protected from feature accretion.

That means:

- new product features should be built above the primitive, not by expanding it
- there should be no "future extension" hooks inside the primitive just in case they are useful later
- optional fields, spare branches, or speculative acceptance paths do not belong in the primitive
- "more expressive" validation is not a goal at the primitive layer

Primitive changes are justified only when they do one of these things:

- fix a soundness or verification bug
- remove ambiguity from canonical encoding or acceptance rules
- simplify the primitive without expanding what is accepted
- replace a broken cryptographic or formal assumption, while retiring the old path

If a proposal is just adding capability, flexibility, programmability, or future room, it should be
rejected at the primitive layer and modeled as composition above it instead.

## Why Feature Accretion Breaks the Primitive

The danger is not just "more code." The danger is that feature accretion changes what validity
means.

Once features are added at the primitive layer:

- the acceptance surface gets wider
- the number of valid states and branches grows
- invariants become conditional on modes, flags, or feature combinations
- reviewers have to reason about interactions instead of a fixed rule set
- implementations drift because different layers interpret optionality differently
- the primitive stops being primitive and starts becoming a platform

Two different families show the problem:

- `Ethereum` shows the Turing-complete version of the problem. Once validity depends on executing
  user programs, you inherit interpreter semantics, resource metering, call interactions, and a
  much larger audit and proof surface.
- `Bitcoin` shows that even non-Turing-complete systems are not immune. Script growth, new opcode
  surfaces, covenant-like behavior, and script-based protocol proposals still enlarge the validation
  surface and coordination burden even when the language remains bounded.

So the lesson is not only "avoid Turing completeness." Non-Turing-complete is important, but it is
not sufficient by itself. The deeper lesson is: do not turn the validation layer into the place
where features keep getting added.

For DSM, adding a script language or programmable acceptance layer would move the system away from a
fixed, analyzable acceptance predicate and toward interpreter semantics. That would undercut the
whole reason to keep the primitive narrow in the first place.

The practical failure mode is simple: people keep adding "just one more useful thing" until the
primitive is no longer nailed down. At that point the system stops being a sharp primitive and
starts becoming a general validation framework. Once that happens, the original point of keeping
the base layer minimal, fixed, and analyzable is lost.

## Repository Mapping

In this repository, the primitive lives primarily in the pure Rust core. The authoritative flow is:

`UI -> MessagePort -> Kotlin bridge -> JNI -> SDK -> Core`

The core defines validity. The SDK mediates I/O. Storage nodes are outside the trust boundary.
The frontend is outside the trust boundary.

## Full Paper

For the full definition, composition model, and boundary checklist, read the PDF:

- [`docs/papers/dsm_primitive.pdf`](../papers/dsm_primitive.pdf)

Back to [Table of Contents](README.md)
