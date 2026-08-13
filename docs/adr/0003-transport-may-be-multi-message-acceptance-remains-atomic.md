<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# ADR 0003 — Transport may be multi-message; acceptance remains atomic

Status: accepted (revision 2)
Date: 2026-08-12

> **Revision 2** corrects a defect in revision 1, which claimed the return leg
> was solved by "using the same mechanism". It was not: a countersigned
> `StitchedReceiptV2` is ~218 KB and does not fit a 128 KiB artifact either, so
> revision 1 relocated the oversized object without shrinking it. The return leg
> is now a **B-side delta** (below). Revision 2 also adds explicit ACK ordering,
> per-role domain separation, a clockless reaping rule, a normative wire budget,
> and per-artifact size tests.
>
> Both acceptance gates are closed:
> 1. **Return leg measured, not estimated.** A B-side delta built from the real
>    field sizes decoded out of the stuck specimen encodes to **101,630 bytes —
>    77.5% of cap, 22.5% headroom**. The model self-checks: real A-side receipt
>    (117,662) + B-specific fields (100,877) = 218,539, reproducing the ~218 KB
>    figure stated independently at `proto/dsm_app.proto:1625-1626`, which also
>    confirms the SMT proofs are shared rather than per-side.
> 2. **ACK ordering is specified** — no ACK is emitted for either artifact
>    individually; see "ACK semantics" below.

## Context

A `wallet.send` envelope captured from the bench rig is **168,400 bytes** against
`MAX_ENVELOPE_BYTES = 128 KiB` (`dsm_storage_node/src/api/transport/b0x.rs:32`).
Every submit fails `413 Payload Too Large` on all three fleet nodes, and the
failure is permanent rather than transient: `sender_outbox.envelope_bytes` stores
the *exact submitted bytes*, so each retry replays an identically oversized
message.

Decoding the specimen's protobuf wire format attributes the size precisely:

```text
envelope                                    168,400
  3 × SPHINCS+ SPX256f signature (49,856)   149,568   88.8%
  everything else                            18,832   11.2%
```

The three blobs are **semantically distinct** (differing SHA-256), not one
signature copied through nested structures:

| | wire path | field |
|---|---|---|
| SIG A | `10.1.10.3.3.5` | `OnlineTransferRequest.signature` |
| SIG B | `10.1.10.3.3.10.12` | `ReceiptCommit.sig_a` |
| SIG C | `10.1.10.3.3.10.14` | `ReceiptCommit.ek_cert_a` |

### What each signature does

- **SIG A** — signed by the sender's long-term AK-rooted key over
  `canonical_operation_bytes`. It is the sole authorization over
  amount / token_id / recipient / policy_commit / nonce / memo. The receive path
  treats the reconstructed protobuf fields as untrusted and sources every
  credited value from the `signed_op` returned by `decode_and_bind_signed`
  (`operations.rs:2493-2521`, `storage_routes.rs:1011-1015`, `:1031-1057`).
- **SIG B** — signed by the sender's per-step ephemeral key `EK_a` over the
  receipt challenge-response target. Presence is mandatory
  (`storage_routes.rs:1533-1541`); verified at `receipts.rs:484`.
- **SIG C** — `ek_cert_a`, signed by the prior chain-head key, authorizing
  `ek_pk_a`. Verified at `receipts.rs:466`. Not redundant with SIG B: SIG B is
  verified *under* the key SIG C authorizes, and SIG C's preimage excludes
  fields 12-20 (`receipt_types.rs:347-355`), so SIG B does not sign the key it is
  verified under.

None is removable today. All three authenticate distinct statements, and each is
consumed by a live `sphincs_verify` on the receiver's accept path.

### The storage node is not a verifier

`grep` for `OnlineTransferRequest` / `receipt_commit` / `sig_a` / `sphincs_verify`
across `dsm_storage_node/src` returns **zero matches**. The payload is stepped
over at `dsm/src/envelope.rs:299` (`skip_field`); the handler spools raw `&body`
(`b0x.rs:313`); the design intent is stated verbatim in-source:

```rust
// b0x.rs:288-289
// NOTE: Storage nodes are dumb mirrors.
// Do NOT validate SmartPolicy / protocol semantics here (clients verify).
```

consistent with
[ADR 0002](0002-storage-acceptance-is-not-cryptographic-endorsement.md). The cap
is enforced by `RequestBodyLimitLayer::new(MAX_ENVELOPE_BYTES)` (`b0x.rs:209-211`),
applied as the outermost layer — so the 413 fires *before* auth and long before
any body parsing.

**Therefore the 128 KiB cap is an admission/transport bound, not a
cryptographic atomic-verification invariant.** No security property requires the
three signatures to arrive in one message.

### Why raising the cap is not the fix

1. **The return leg is worse.** A countersigned `StitchedReceiptV2` is documented
   at ~218 KB — "two SPHINCS+ signatures, two ek_certs, and both SMT proof sets"
   (`proto/dsm_app.proto:1625-1626`) — which is 1.7× the cap. Any fix that only
   shrinks the outbound message leaves the return path broken.
2. **The cap bounds real work.** `envelope.rs:326-344` decodes and re-encodes the
   full body, so prost copies all 149,568 signature bytes twice without ever
   interpreting them; retrieve fans that out to 64 envelopes with no
   response-size limit (`b0x.rs:33`, `:411-434`).
3. **The declared bounds are already unsatisfiable.** `receipt_commit` is
   declared `max_len = 131072` (`proto:3331`) — numerically *equal to* the
   whole-envelope cap containing it — and `ArgPack.body` is `262144`
   (`proto:1627`), 2× it. `dsm_max_len` is unenforced by generated code, so
   nothing catches this today.

### Root discrepancy

The field is documented as canonical in **two** places — the proto contract and
the Rust submission params:

```protobuf
// proto/dsm_app.proto:3330-3331
// §4.2 ReceiptCommit canonical protobuf bytes — SMT proofs for this transition
bytes receipt_commit = 10 [(dsm_max_len)=131072];
```

```rust
// b0x_sdk.rs:266
// receipt_commit (§4.2 ReceiptCommit canonical protobuf) — length-prefixed
```

but the producer builds *both* forms and ships the full evidence form:

```rust
// app_router_impl.rs:1408
let (receipt_commit_bytes, receipt_canonical_bytes) = { ... };
// app_router_impl.rs:1863
receipt_commit: receipt_commit_bytes,   // the FULL form
```

`receipt_canonical_bytes` exists in the same scope and is used at `:1912`,
`:1970`, `:2031` — never for b0x. This is a **naming/contract defect, not a
serialization bug**: the receipt implementation deliberately includes fields 12/13
in the wire form when non-empty (`receipt_types.rs:455`, `:465`), and the
recipient genuinely requires them.

## Decision

**Transport may be multi-message; acceptance remains atomic.**

Split the cryptographic evidence out of the semantic message and bind it by
content address.

```text
small semantic message ── digest ──► large cryptographic evidence object
```

### Message shapes

```text
TransferEnvelope
├── canonical_operation_bytes
├── SIG A
├── receipt_evidence_digest : 32 B
├── receipt_id / correlation id
└── routing metadata

ReceiptEvidenceEnvelope
├── receipt_id
├── full StitchedReceiptV2
│   ├── canonical receipt fields (1-11)
│   ├── sig_a / sig_b
│   ├── ek_cert_a / ek_cert_b
│   ├── ek_pk_a / ek_pk_b
│   ├── Kyber material
│   └── SMT proofs
└── digest binding
```

### Content addressing, domain-separated BY ROLE

```text
receipt_evidence_digest_a =
    BLAKE3("DSM/receipt-evidence/A/v1\0" ‖ full_a_side_receipt_wire_bytes)

receipt_evidence_digest_b =
    BLAKE3("DSM/receipt-evidence/B/v1\0" ‖ b_side_delta_wire_bytes)
```

Hash the **full wire bytes** (`to_full_protobuf`, `receipt_types.rs:467-470`),
NOT `compute_commitment()`. The commitment `C` covers fields 1-11 and hard-zeroes
12-20 (`receipt_types.rs:334-357`), so a `C`-addressed object could be served
with substituted signatures. The digest must bind the exact bytes whose
signatures the receiver will verify.

A bare `H(full_bytes)` is **not** sufficient. Every evidence artifact is a byte
blob, so an undifferentiated digest makes an A-side artifact, a B-side delta, and
any future evidence type structurally interchangeable — a reference obtained in
one role could be satisfied by an object produced for another. The role is part
of the identity, so it belongs in the domain tag, per
[ADR 0001](0001-three-domain-separation-constructions.md).

### Acceptance state machine

The recipient applies nothing while only one half is present. It durably stages
whichever arrives first and proceeds only when the digest binds and all existing
verification succeeds.

```text
transfer first   → stage, await evidence
evidence first   → stage, await transfer
duplicate        → idempotent, no double-apply
both present     → verify → apply → countersign/ACK
digest mismatch  → reject, no apply
```

Ordering is irrelevant by construction. **The existing presence gates must become
fetch-and-bind gates, fail-closed** — `storage_routes.rs:1174-1182` (empty
`receipt_commit` → reject, no ACK) and `:1263-1300` become
"digest present ∧ object staged ∧ `BLAKE3(object) == digest`". Otherwise the
split silently converts a mandatory gate into an optional one.

### ACK semantics — transport ACK must not outrun semantic acceptance

This is the most dangerous part of the change, more so than the size bug.

If the recipient ACKs the small transfer artifact merely because it durably
staged it, and the sender reads that ACK as recipient acceptance, **the sender
can finalize while the receipt evidence is still absent, unverified, or
invalid.** The split would then have manufactured a window in which a transfer
is settled on one side and cryptographically unproven on the other.

Required semantics:

```text
stage either half durably           → ACK NOTHING
both halves present
  ∧ digest-bound
  ∧ cryptographically verified
  ∧ canonical apply completed       → ACK the logical transfer
```

Duplicates arriving while waiting are harmless and must be idempotent. A staged
half is a local durability fact, never a protocol acknowledgement. No ACK may be
emitted for either artifact individually.

### Sender durability — one proposal owns every artifact

Preserve the existing forward-only/outbox semantics. **One logical outbox
proposal owns the deterministic IDs and the exact wire bytes of every artifact
it will emit**, and all of them are persisted atomically before any becomes
deliverable.

The current outbox deliberately freezes exact submitted bytes so a retry
re-sends the same logical send rather than reconstructing a new one
(`sender_outbox.envelope_bytes`). That invariant must survive the split: two
artifacts, one proposal, one atomic commit, byte-frozen. Splitting one durable
artifact into two is exactly how the "one half escaped but local state rolled
back" class of bug returns — the class §16.6 exists to prevent.

### Return leg — a B-side delta, NOT another full receipt

A countersigned `StitchedReceiptV2` is ~218 KB (`proto:1625-1626`). Carrying it
as a `ReceiptEvidenceEnvelope` **does not fit**: 223,232 bytes with the measured
wrapper, 170.3% of the cap, over by 92,160. Making the return leg "the same
mechanism" would only relocate an oversized object, not shrink it.

The sender already possesses the complete A-side receipt it created. The receiver
must therefore return only what the sender lacks:

```text
ReceiptCountersignEnvelope
├── receipt_id
├── receipt_evidence_digest_a      : 32 B   (what is being countersigned)
├── B-side evidence delta
│   ├── sig_b
│   ├── ek_cert_b
│   ├── ek_pk_b
│   └── B-side proof material
└── digest binding (receipt_evidence_digest_b)
```

The sender deterministically reconstructs the countersigned receipt from its
retained A-side object plus this delta, then verifies it. Nothing A-side is
retransmitted.

**This delta MUST be measured with real SPHINCS-sized material before
implementation.** If it still exceeds the cap, split the B evidence again by
content-addressed digest — do not raise the limit.

## Scope of this change

**In scope: transport composition only. Security semantics identical.**

Explicitly NOT in this change, so that any behavioural difference is
attributable to the split alone:

- `MAX_ENVELOPE_BYTES` is unchanged.
- SIG A is not removed.
- No signature preimage changes.
- No change to what is verified, only to which message carries it.

## Consequences

Wrapper framing measured from the specimen (Envelope + UniversalTx + UniversalOp
+ Invoke + ArgPack) is **579 bytes**, carried forward into every projection
below.

```text
artifact                                    bytes    % of cap   headroom
────────────────────────────────────────────────────────────────────────
TransferEnvelope                           50,770      38.7%     80,302
ReceiptEvidenceEnvelope (A-side, full)    118,241      90.2%     12,831   ← NARROW
ReceiptCountersignEnvelope (B delta)       must be measured with real material
────────────────────────────────────────────────────────────────────────
(rejected) countersigned full receipt     223,232     170.3%   −92,160   ← DOES NOT FIT
```

The transfer artifact gains 3.15× the margin needed. **The A-side evidence
artifact does not**: at 90.2% it has ~12.8 KB of room, which is enough today and
brittle tomorrow — one added proof or a second Kyber field puts it over. It is
accepted here only because this change is deliberately scoped to transport
composition, and because the operation-digest cleanup that follows may remove
SIG A from the *transfer* artifact rather than this one. If the A-side evidence
object grows, it is the next candidate for content-addressed sub-splitting, on
the same principle: split, never raise the cap.

Minimum needed to clear the cap is 37,329 bytes; this yields **3.15×** that.
The margin is the point, not a bonus — this is the *second* occurrence of this
failure mode. `DEVICE_STATE_VERSION` was bumped to `0x06`
(`bcr.rs:88`, `device_state.rs:236-240`) to strip ~50 KB per relationship from
the device head for the same reason, and that change did **not** fix this 413
because the envelope never carried the head. A fix that leaves the envelope near
the cap (e.g. removing one 49,856-byte signature → 118,544 = 90.4% of cap) is not
a fix.

The `ReceiptEvidenceEnvelope` route must be sized with a written rationale, the
way the sibling route was: `MAX_ANCHOR_BYTES` = 256 KiB "because two SPHINCS+
SPX256f signatures (~49.9 KiB each) … fit well under 256 KiB"
(`recovery_anchor.rs:39-41`).

### Costs

- Two round trips (or two spool entries) per transfer instead of one.
- More states to test. The failure modes move from "message too large" to
  "half present" — which is why the state machine above is fail-closed by
  default.
- A staging table, and the reaping rule below.

### Reaping — clockless, and never destructive of a live transfer

Staged halves cannot accumulate without bound, but cleanup must not create a
worse failure than the one it prevents. **Reaping a half while its counterpart
can still legally arrive converts "half present" into permanent limbo** — the
transfer is forward-only, so the sender will not reissue a new logical send.

Therefore:

- Cleanup is driven by **deterministic lifecycle state or iteration**, never by
  wall-clock age. Wall-clock in a consensus-adjacent path is prohibited
  repo-wide, and here it would additionally make reaping racy against a slow
  network.
- A half may only be discarded once its logical transfer has reached an explicit
  **terminal state** — applied, or tombstoned by a definite protocol outcome.
- Absent a terminal marker, a staged half is retained. Unbounded-but-correct is
  preferable to bounded-but-lossy for forward-only value transfer; if growth
  becomes a real problem, the answer is an explicit terminal tombstone, not a
  timer.

## Wire budget (normative)

Artifact size is an **explicit protocol budget**, not an implementation
accident. The three current shapes, measured from real SPHINCS-sized material
against `MAX_ENVELOPE_BYTES = 131,072`:

| artifact | encoded bytes | % of cap | headroom |
|---|---|---|---|
| `TransferEnvelope` | ~50,770 | 38.7% | 80,302 |
| `ReceiptEvidenceEnvelope` (A-side) | ~118,241 | **90.2%** | 12,831 |
| `ReceiptCountersignEnvelope` (B delta) | ~101,630 | 77.5% | 29,442 |

**Normative constraint.** The B-side countersign artifact contains exactly two
SPHINCS+ signature-sized objects: `sig_b` and `ek_cert_b`. Adding any additional
SPHINCS+-sized object to it requires re-evaluating transport composition and, if
necessary, content-addressing the evidence into additional artifacts. Its
headroom is 29,442 bytes — **less than one signature (0.59×)** — so a third
signature-sized field does not degrade this shape gradually, it breaks it
outright.

The same applies with less slack to the A-side evidence artifact, which is the
one to watch hardest: at 90.2% it has ~12.8 KB, and 99,712 of its bytes are two
signatures.

**Rule.** Any change to receipt evidence fields must run the real-size wire-budget
regression below. *A new SPHINCS+-sized field on either evidence leg is a
transport-design change, not an ordinary schema extension.*

## Required regression tests

### CI invariant — real-size wire budget

```text
real-size encoded artifact < 131,072 bytes
```

asserted for **all three** shapes above, using production-size SPHINCS+ material.
This is the guardrail that converts the size cliff into a checked constraint. It
must fail the build, not warn.

### Size — per artifact, per encoded envelope

Construct **real SPHINCS-sized** A-side and B-side evidence (two signatures, two
ek_certs, both proof sets) and assert that **every actual encoded `Envelope`
body — not merely the inner object — is `< MAX_ENVELOPE_BYTES`**. The distinction
matters: the inner object plus 579 bytes of wrapper is what the node's
`RequestBodyLimitLayer` measures, and the A-side artifact sits at 90.2%, so a
test that measures only the inner object would pass while the wire message
failed.

Assert per artifact, not per logical transfer. A logical transfer that "fits" in
aggregate proves nothing about the individual messages that actually get
submitted.

### Behaviour — the states the split creates

| case | required outcome |
|---|---|
| transfer arrives first | stage, no ACK, no apply |
| evidence arrives first | stage, no ACK, no apply |
| both present, digest binds, verification passes | verify → apply → ACK |
| duplicate of either half | idempotent, no double-apply |
| digest mismatch | reject, no apply, no ACK |
| one half permanently missing | no apply, no ACK, staged half retained |
| crash/restart between halves | staged half survives; completion still possible |
| ACK timing | no ACK is emitted for either artifact individually |

This design failure was found by hardware, not by CI, because no test ever built
a full-size receipt and measured the resulting message. A synthetic receipt with
empty or short signatures passes today and proves nothing — and the same blind
spot is what let a field declared `max_len = 131072` inside a 131,072-byte cap
survive review.

## Sequence

```text
split  →  hardware transfer settles  →  operation-digest binding
       →  adversarial tests  →  optional SIG-A removal
```

The operation-digest binding is the right cryptographic cleanup but does **not**
solve the return-leg size problem, so it follows rather than leads. It is also
cheaper than it appears: `wallet.send` currently passes
`session_binding: &commitment` alongside `commitment: &commitment`
(`app_router_impl.rs:1553`), making the EK-signed target literally
`H(C ‖ C)` — the slot carries no independent information, and the doc states the
binding is "added at the response-target level, not in the receipt body"
(`receipts.rs:38-52`). Substituting

```text
session_binding = H("DSM/canonical-apply-op-digest/v1" ‖ canonical_operation_bytes)
```

yields `H(C ‖ operation_digest)` with **no receipt format change and no new
field**, and establishes the invariant: *a receipt authorization is valid only
for one exact canonical operation.* Only then is SIG A a candidate for removal.

## Evidence

The specimen is retained on the bench rig: 8XK `sender_outbox`, submission
`RX6BA3TY6KRDEBVXGXNCTHWVT0`, 168,400 bytes, unmodified. It reproduces the 413
deterministically and should not be cleared until the split is proven.
