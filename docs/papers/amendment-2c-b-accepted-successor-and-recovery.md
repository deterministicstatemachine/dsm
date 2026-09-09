# Amendment 2c-B — the accepted-successor / recovery class, and two frozen foreign grammars

Status: **ENCODING CLOSURE FOR THE MARKET SHAPE. VERIFICATION CLOSURE AND PRODUCTION ENABLEMENT
REMAIN GATED ON 2c-C.** 2026-09-07.

Normative and encoder-free, per the registry preamble.
Governs `docs/papers/ccb-object-registry.md` class `0x0031`, completes `0x0033` field 6, and
freezes the foreign byte grammar `0x000F` field 4 signs.

## Context

Amendment 2c-A froze the canonical settlement objects and deliberately stopped one field short of
a complete market bundle:

```text
2c-A fixes   the derivation of b and ALL outer canonical structure
Owner close  ENCODABLE once the exact prepared close_authorization bytes are supplied
Market       INTENTIONALLY UNINSTANTIABLE until 2c-B closes MarketTerms field 6
```

`MarketTerms` (`0x0033`) field 6 `recovery_material` is **mandatory** and its nested class is
2c-B's. Because it is mandatory there is no encodable market `MarketTerms`, therefore no encodable
market `SettlementBundle`, therefore **no conformant market `b`**. Registry §6 names that as the
single remaining encoding blocker, and states the exclusivity affirmatively: *"Nothing else about
either object is open."*

### A boundary correction this amendment propagates

2c-A, the registry and the decomposition all say the owner-close shape is *"fully constructible
today"*. That is too strong, and **2c-B is the reason**: 2c-B owns and freezes
`CloseAuthorizationPreimageV1`. The accurate statement, carried into every place that currently
claims otherwise:

> Under 2c-A, an owner-close `SettlementBundle` is **fully encodable once the exact prepared
> `close_authorization` bytes are supplied**. 2c-B freezes the foreign byte grammar required to
> **construct and verify a fresh** `close_authorization`.

This is a wording correction to a boundary, not a field-table change. Nothing about `0x000F`
field 4's number, type or optionality moves.

### Why the field is mandatory, verified rather than assumed

A market settle is **not** reconstructible from `C_dsm+` alone. Two premises of the original claim
needed correction, and both are stated here so the amendment rests on what is true:

- `route_commit_bytes` **is** byte-identical in `B` today, and stops being derivable only once
  2c-A turns `selected_route` into a nested CCB `Route`. The need is created by the 2c-A cut, not
  inherent to the operation.
- The SPHINCS+ signature **is** reproducible by the crashed device itself — this implementation is
  derandomised, `R = BLAKE3_keyed(sk_prf, m)` — but by no other party, and only after every other
  operation field is reproduced bit-exactly.

The genuinely irreducible items are `entropy`, the identity pair (`rel_key`, `counterparty_devid` —
`DevID = H(DSM/devid ‖ AK_pk ‖ AttA)`, and `AttA` is nowhere in `B`), and **four operation fields
nothing validates**: `sigma` (hard-coded zeros today), `settler_public_key`, `settler_devid` and
`signature`, all caller-supplied.

**Nothing persists the prepared-but-uncommitted settle.** The advance is prepare→write→commit
inside one SQLite transaction, so "prepared but uncommitted" is not a durable state at all; the
window between `bind_settlement` returning `Committed` and the advance holds **zero** reconstruction
material. That window is what this amendment closes.

### The constraint shaping every answer

Registry §2.10: protobuf transport bytes are never a valid CCB blob and must never be hashed or
signed as if they were. `DsmSuccessorEvidenceV1` violates it **twice** — a content address computed
over prost bytes, and prost determinism used *as* the canonical form. The decomposition states the
requirement directly: the new class **must not be the existing prost bytes canonized**.

---

## Owner rulings

### Ruling 1 — `c_dsm_plus` is dropped. Recompute, never restate.

It is **doubly** derivable: `relationship_chain_tip_v2` recomputes it from the six inputs, and it
equals `B.market_terms.trader_successor`. Carrying it makes three statements of one fact.

Decisive: the existing verifier **already recomputes and compares** rather than trusting the carried
value — its mismatch arm exists precisely because the field is not accepted as authority. The field
supplies nothing a verifier acts on.

A standalone consumer reached through `EconomicAdmissionManifest` still has the derived value; it
does not vanish merely because it is not serialised. An independently addressed canonical object
authenticates itself from its own preimage and signature, and does not need a second copy of its
own derived commitment to serve as a comparison target.

**Rejected:** keeping it as the standalone equality gate. That preserves a restated derived value
and creates a field that can disagree with its own preimage, which the validity rule would then
have to refuse.

### Ruling 2 — the close preimage is frozen as a byte grammar, not as a function name

Normatively: *"sign `CloseAuthorizationPreimageV1`, encoded as follows…"* — **never** *"sign
`Operation::to_bytes`"*. The shipping Rust function is the **current implementation** of that
grammar, byte-identical to it: **evidence of the byte grammar, never the normative authority.**

This distinction is the whole point of the ruling. It stops a future Rust refactor from silently
changing a protocol signing preimage.

**Rejected:** defining a CCB close preimage. It would invalidate every existing close signature,
force re-authorisation, and contradict the standing one-signed-artifact doctrine — which is why
2c-A reused the operation rather than inventing a second commitment. **Also rejected:** deferring
to 2c-C, which would leave the owner-close shape resting on an unfrozen preimage.

### Ruling 3 — 2c-B declares the beta identity cut it causes

Re-basing the evidence address off prost changes `CCB(0x001C)`, hence the manifest address, hence
the signed `0x001B` root-claim identity:

```text
old prost-addressed evidence -> old evidence address
    -> old EconomicAdmissionManifest -> old root-claim

2c-B CCB cut -> new canonical evidence bytes -> new evidence address
    -> new manifest address -> new root-claim identity
```

Existing prost-addressed admission artifacts are **not** migrated, grandfathered or dual-resolved.

**This does not by itself require schema bumps of `0x001C` or `0x001B`**, and the wording was
confirmed before the sentence was frozen: `0x001C` field 4 is
`DsmSuccessor { evidence_addr: [u8; 32] }`, documented as *"the exact `C_dsm+` / `sigma_dsm`
accepted"* and encoded as a bare `push_digest32`. The field means **the content address of the
evidence object**; the address derivation lives in the evidence object's own module. No
prost-derived addressing is frozen into the field's semantics. Both enclosing objects retain the
same canonical types and the same meanings — content addresses of the referenced objects.

2c-C still owns the complete `0x001B`–`0x0030` registry and verification absorption audit.

**Rejected:** deferring the consequence to 2c-C, which would leave 2c-B knowingly changing
addresses without declaring what happens to dependent artifacts. **Also rejected:** dual
resolution, which recreates legacy coexistence.

### Ruling 4 — the linkability consequence is accepted and stated

```text
1. Required for recovery: exact operation bytes must survive a crash.
2. Consequence: settler_devid and settler_public_key become permanently
   committed to the market bundle.
3. Classification: reveals NO secret signing material, but creates durable
   transaction-to-DSM-identity linkability.
```

**With the correction:** this is *not* already shipped. `DlvSettle` does not route through economic
admission today — the settle path passes no admission — so the disclosure is introduced when the
5c-2 settle path begins using the economic-admission/recovery construction. It is not a property of
the currently shipped path merely because the fields exist elsewhere.

Identity unlinkability is recorded as **future work** and does not block 2c-B. A commitment-only
variant would need an opening protocol and a third-party recovery story — a new privacy protocol,
not a field-table cleanup.

---

# §5.23 `DsmSuccessorEvidence` — class `0x0031`, schema 1

**Substrate**, on the same footing as `0x0018`–`0x001A`: allocated from the single namespace,
carrying the same immutability rules, and **excluded from Rev 15's §4 closure count**.

`evidence_addr = H_dom(DSM/economic-dsm-successor-evidence/v1, CCB(DsmSuccessorEvidence))` —
computed over the **canonical CCB bytes**, never over protobuf. Protobuf remains its transport
carrier and nothing more.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `rel_key` | `digest32` | not derivable from `B`: `DevID = H(DSM/devid ‖ AK_pk ‖ AttA)` and `AttA` is nowhere in the bundle |
| 2 | `embedded_parent` | `digest32` | must equal `B.market_terms.trader_parent`; carried so the equality is **checked**, not assumed |
| 3 | `counterparty_devid` | `digest32` | same `AttA` problem; the settle is a self-loop, so this is the trader's own DevID |
| 4 | `operation_bytes` | `bytes` | a `DlvSettleOperationPreimageV1` (§ below). Reconstruction is not total, and the signature is inside the preimage |
| 5 | `entropy` | `bytes`, **semantically exactly 32** | a BLAKE3 output: `H_dom(DSM/state-entropy, prior_entropy ‖ op_bytes ‖ prior_hash)`. A pure fold with no RNG, but folded from the device's head tip entropy; carrying it makes the successor recomputable **by anyone**, not only by the device that crashed. Schema 1 **refuses any length but 32** |
| 6 | `encapsulated_entropy` | optional `bytes` | **always absent** in this profile — but the chain-tip preimage distinguishes absent (`0`) from present-and-empty (`1,0`), so absence is **encoded, never flattened** (§2.3). Schema 1 refuses present |
| 7 | `sigma_dsm` | `bytes`, **semantically exactly 49,856** | one `SPHINCS_PLUS_SPX256F` signature (§3.1) over `H_dom(DSM/economic-substrate-sign/v1, G ‖ DevID ‖ C_dsm+ ‖ operation_digest)`. Carries the signature material required for later foreign verification. Schema 1 refuses any other length |

`c_dsm_plus` is **not** a field (ruling 1).

**CCB field numbers are their own namespace** and need not agree with the protobuf's (§2.10), so
`sigma_dsm` is field 7 here and field 8 in the transport message. Stated so no implementer reads
the gap as an omission.

### Normative exclusions

`vault_id`, `parent_sequence`, `parent_binding`, `route_commit_bytes`, `external_commitment_x`,
both policy commits, both amounts and `settlement_receipt_id` are **not carried as separate fields
of `0x0031`**.

```text
Values already present inside operation_bytes are not duplicated as standalone
0x0031 fields.

Where 2c-B explicitly defines a cross-object equality, that equality is checked
here. All remaining semantic correspondence between the reconstructed DlvSettle
and the settlement / economic state is deferred to 2c-C.
```

`operation_bytes` is the **authoritative recovery copy** for reconstructing the exact prepared
successor — necessarily so for `route_commit_bytes`, which stops being derivable from `B` once
`selected_route` becomes a nested CCB `Route`.

### The complete set of cross-object comparisons 2c-B performs

```text
2c-B performs ONLY the cross-object comparisons stated explicitly in this amendment:

    evidence.embedded_parent
        == B.market_terms.trader_parent

    relationship_chain_tip_v2(evidence inputs)
        == B.market_terms.trader_successor

    and the canonical DlvSettleOperationPreimageV1 syntax checks.

Any further comparison between fields parsed from operation_bytes and facts
derivable from B, the authenticated V_n, the selected route, or economic state
is part of ValidDlvSuccessor and is owned by 2c-C unless this amendment
explicitly states otherwise.
```

That list is **exhaustive by construction**. An implementer reading 2c-B knows exactly which
comparisons are due here and that everything else is 2c-C's.

### Endianness

Stated because silence here is a divergence waiting to happen. **CCB lengths are big-endian**
(`u32_BE`); `relationship_chain_tip_v2`'s internal preimage and the two foreign grammars below are
**little-endian**. These are separate preimages, so it is not a contradiction — but an
implementation that conflates them produces different bytes for the same object.

---

# Structural reconstruction validity

A market bundle is invalid unless field 6 decodes, re-encodes to itself, and satisfies the
conjuncts below **in this order**.

## First — the encoding-level conjunct

Without it the chain-tip equality permits **arbitrary** `operation_bytes`, because a producer who
computed `trader_successor` over those same arbitrary bytes satisfies it trivially.

```text
op = decode_DlvSettleOperationPreimageV1(evidence.operation_bytes)

require:
    decode succeeds
    decode consumes ALL bytes
    re-encode(op) == evidence.operation_bytes
    discriminator == 26
    mode == Unilateral
    every fixed-length semantic field has its required length
    signature has the schema-1 SPX256f signature length
```

## Then — the chain-tip equalities, over those canonical bytes

```text
relationship_chain_tip_v2(<its six inputs>) == B.market_terms.trader_successor
its embedded_parent                          == B.market_terms.trader_parent
```

A mismatch is a **refusal, not a repair**. Identity derives from `rel_key` and `counterparty_devid`
only, **never from the operation body**.

This section establishes **structural reconstruction equality only**. It does not perform the
semantic or cryptographic authority validation 2c-C owns: it establishes that the bytes are a
well-formed `DlvSettle` of the frozen grammar, not that the settle is authorised.

Without these conjuncts field 6 is decoration — today `settlement_bundle::validate` width-checks
the two successor fields and **never reads `recovery_material` at all**.

> **Partially corrected 2026-09-09 by the 2c-A.1 adopting change (#799), and the headline still
> stands.** `settlement_bundle::validate` is deleted; field 6 is now a mandatory nested `0x0031`
> that is strictly decoded and round-tripped, so it is no longer unread bytes. But **none of the
> conjuncts above is implemented**: nothing decodes `operation_bytes` as
> `DlvSettleOperationPreimageV1`, nothing recomputes `relationship_chain_tip_v2`, and nothing
> compares `embedded_parent` with `B.market_terms.trader_parent`. 2c-B is documentation-only and no
> adopting change has been assigned these conjuncts, so field 6 remains decoration in exactly the
> sense this paragraph means. Recorded here rather than in a code comment, because the code comment
> that claimed the equality was checked was itself the defect (corrected in the same change).

---

# The two frozen foreign byte grammars

Neither is a CCB object. Both stay **outside** the CCB object graph, carried by CCB `bytes` fields.
CCB may carry foreign bytes; what it may not do is *be* protobuf (§2.10). Neither grammar is
protobuf — both are hand-rolled and have no protobuf mirror anywhere.

## Shared primitives, stated once

```text
u8            one byte
u32 / u64     LITTLE-ENDIAN fixed width
bytes(x)      u32_LE(len(x)) ‖ x
              -- EVERY 32-byte value uses this, length-prefixed, NEVER bare.
                 This is the OPPOSITE of CCB's digest32 and is deliberate:
                 these are foreign grammars, not CCB objects.
mode          u8   Bilateral = 0, Unilateral = 1
```

## `CloseAuthorizationPreimageV1` — what `0x000F` field 4 signs

| # | Field | Semantic type | Encoding |
|---|---|---|---|
| — | discriminator | — | `u8` = **28** |
| 1 | `vault_id` | 32-byte id | `bytes` |
| 2 | `leg_a_policy_commit` | digest | `bytes` |
| 3 | `leg_a_amount` | base units | `u64_LE` |
| 4 | `leg_b_policy_commit` | digest | `bytes` |
| 5 | `leg_b_amount` | base units | `u64_LE` |
| 6 | `parent_sequence` | generation | `u64_LE` |
| 7 | `new_sequence` | generation | `u64_LE` |
| 8 | `fee_bps` | basis points | `u32_LE` |
| 9 | `signature` | **cleared** | `bytes` of length 0 → the four bytes `00 00 00 00` |
| 10 | `mode` | fixed `Unilateral` | `u8` = `1` |

`0x000F` field 4 is a `SPHINCS_PLUS_SPX256F` signature over **exactly these bytes**, with no
domain-tag hash wrapper — the message is passed to the signer directly.

`new_sequence` is `parent_sequence + 1` and `mode` is fixed, so both are reconstructible; they are
in the grammar because they are in the signed bytes.

## `DlvSettleOperationPreimageV1` — what `0x0031` field 4 carries

Freezing this is what turns "constructible" from *"if you know what the current Rust emits"* into a
rule two independent producers can follow.

| # | Field | Semantic type | Encoding |
|---|---|---|---|
| — | discriminator | — | `u8` = **26** |
| 1 | `vault_id` | 32-byte id | `bytes` |
| 2 | `owner_public_key` | SPX256f public key, 64 B | `bytes` |
| 3 | `owner_devid` | digest | `bytes` |
| 4 | `owner_genesis` | digest | `bytes` |
| 5 | `input_policy_commit` | digest | `bytes` |
| 6 | `output_policy_commit` | digest | `bytes` |
| 7 | `parent_sequence` | generation | `u64_LE` |
| 8 | `parent_binding` (`c_n`) | digest | `bytes` |
| 9 | `route_commit_bytes` | the signed quote | `bytes` |
| 10 | `external_commitment_x` | digest | `bytes` |
| 11 | `input_amount` | base units | `u64_LE` |
| 12 | `output_amount` | base units | `u64_LE` |
| 13 | `fee_bps` | basis points | `u32_LE` |
| 14 | `sigma` | 32-byte unlock proof | `bytes` |
| 15 | `settler_public_key` | SPX256f public key | `bytes` |
| 16 | `settler_devid` | digest | `bytes` |
| 17 | `settlement_receipt_id` | digest | `bytes` |
| 18 | `signature` | SPX256f over this grammar with field 18 cleared | `bytes` |
| 19 | `mode` | fixed `Unilateral` | `u8` = `1` |

The settler signs with field 18 cleared, then the signature is written back into field 18 — which
is why the operation **cannot be signed after the advance**: the signature is inside
`operation_bytes` and therefore inside `C_dsm+`, so a transition committed unsigned cannot be signed
afterwards without rewriting the tip and every descendant.

## The authority rule, stated once for both

> The shipping `Operation::to_bytes` is the **current implementation** of these grammars and is
> byte-identical to them. It is **evidence of the byte grammar, never the normative authority.**
> A future refactor that changes these bytes changes the protocol and requires an amendment.

---

# The `C_T^+` correspondence — a spec correction, not a transcription

Rev 15 Def 6.26 requires `C_T^+` to commit *"the trader relationship/chain identity, the exact
accepted `trader_parent → trader_successor` transition, and the post-advance authenticated state
root `R_T^+`"*.

**DSM has no such commitment.** `relationship_chain_tip_v2` commits `rel_key`, `embedded_parent`,
`counterparty_devid`, `operation_bytes`, `entropy` and `encapsulated_entropy` — succession facts
only. No state root. And `sigma_dsm`'s signing digest, over `G ‖ DevID ‖ C_dsm+ ‖ operation_digest`,
does not cover one either.

**Normative statement.** For SoFi, the ordinary accepted-successor authentication required by Def
6.26 **is a cryptographically linked pair, not a single object**:

```text
sigma_dsm                    -> authenticates C_dsm+ and the operation
validated economic admission -> derives R_T^+ from that exact C_dsm+
```

A conforming verifier establishes the same fact by verifying `sigma_dsm` over `C_dsm+` **and**
deriving `R_T^+` through the validity walk that binds that exact `C_dsm+`. Rev 15's prose, which
reads as though one commitment contains the root, is corrected accordingly:

> **The relationship chain tip does not and must not contain the economic root.**

`R_econ` is the sole authenticated balance representation, and bending an ordinary DSM commitment
to carry it would put a SoFi requirement inside a commitment every non-SoFi path also computes.

## The walk's shape, and where each step is owned

2c-B states the **shape**; 2c-C makes each step **reproducible**. Each step below names its
dependency rather than specifying it:

```text
previously validated R_econ           -- 2c-C: register resolution, P0-P6
  -> verified economic transition / write set   -- 2c-C: ValidDlvSuccessor
  -> manifest + authority evidence              -- 2c-C: 0x001B-0x0030 absorption
  -> exact DsmSuccessorEvidence (0x0031)        -- 2c-B: THIS amendment
  -> VALIDATED post-economic root R_T^+         -- 2c-C
```

**Registration is not validation.** A malicious trader registers an arbitrary root perfectly
consistently; the register establishes non-equivocation, not transition validity. A `TA_B` verifier
that checked only a signed claim naming some root would leave the forged-root attack alive in a
different shape. That verifier is 2c-D's to write, over 2c-C's walk.

**2c-B disclaims verification closure**, matching 2c-A's posture. Writing P0–P6, SMT bit ordering
or register-cell formats here would absorb 2c-C's work.

---

# Encoding closure is not production enablement

```text
2c-B closes encoding / construction.

    complete market B is canonically constructible
    encoder and decoder implementation may begin

Production acceptance / binding of the new market bundle remains GATED on
2c-C's ValidDlvSuccessor and ordinary-DSM authority / signature verification.

    encoding closure  !=  verification closure  !=  production enablement
```

This rule exists because of a specific hole. Four `DlvSettle` fields are caller-supplied and never
checked: `sigma` (hard-coded zeros), `settler_public_key`, `settler_devid` and `signature`. The
chain-tip conjunct **pins** them — any difference changes `C_dsm+` — so a reconstruction is exact.
Nothing establishes they are **meaningful**, and `settler_public_key` in particular is never
compared with the key that actually signed.

Without this rule an implementer could satisfy both reconstruction equalities and treat a
structurally reproducible but semantically invalid settle as acceptable.

---

# The size consequence

The owner-close bundle is 50,330 bytes and carries **one** signature. A complete market bundle
carries **three**: the `initiator_signature` inside `route_commit_bytes`, the `DlvSettle`
`signature`, and `sigma_dsm`.

Measured by encoding the objects from the field tables in this amendment, with a pinned fixture
(64-byte public keys, a 200-byte RouteCommit body plus its signature, zero-length nothing):

```text
CloseAuthorizationPreimageV1, signing form         150 bytes
DlvSettleOperationPreimageV1                   100,446 bytes   (2 signatures inside)
0x0031 DsmSuccessorEvidence                    150,447 bytes   (adds sigma_dsm)

three SPX256f signatures                       149,568 bytes   -- the FLOOR

vs 512 KiB authenticated ingress cap              28.7%   ~3.5x margin
vs 128 KiB b0x envelope cap                        115%   EXCEEDS
```

Two consequences.

**The market margin is roughly a third of the owner close's** — 3.5x against 10.4x. Still passing,
but the market bundle is no longer the comfortable case, and this is a recorded number rather than
an assumption.

**A market bundle does not fit the `b0x` envelope at all.** The earlier finding that a settlement
bundle never traverses `b0x` therefore stops being a convenience and becomes **load-bearing**:
routing one there would be a defect, not a degradation. This is the same shape as the incident that
produced the repository's prior 413 — a cached state embedding one SPHINCS+ signature overran the
128 KiB envelope, and was fixed by shrinking the payload rather than raising the cap.

These figures are exact for the stated fixture. A real bundle's `route_commit_bytes` and nested
`Route` will differ; the **floor** of three signatures does not.

---

# Registry and cross-document edits

## `ccb-object-registry.md`

- **§3** — add the `0x0031` row, marked **substrate**, pointing at §5.23.
- **§5.20** — make `MarketTerms` field 6's type cell concrete: nested `0x0031` schema 1.
- **§5.23** — the new field table above.
- **§3 / §4 / §6 / §7** — flip `0x000E` and `0x0033` from A-stage-frozen to **fully specified**;
  update §4's counts; remove the "encoding-blocked" language from §6 and record that the blocker is
  closed; update §7's 2c-B bullet.

## The owner-close boundary correction

Propagate to every place that overstates it — located, not assumed:

```text
ccb-object-registry.md   §4 status list   "fully constructible today."
ccb-object-registry.md   §5.19            "...and is fully constructible today."
ccb-object-registry.md   §7               "The owner-close shape is fully constructible; ..."
amendment-2c-a...        §5.19            "unaffected by that particular encoding dependency"
amendment-2c-a...        worked encoding  "2c-A can carry a complete owner-close encoding example"
```

Each becomes: encodable **once the exact prepared `close_authorization` bytes are supplied**, with
2c-B freezing the grammar needed to construct and verify a **fresh** one. 2c-A's worked example
stays valid as written — it encodes *given* frozen signature bytes — but its surrounding claim must
stop implying the close shape needed nothing from 2c-B.

## `amendment-2c-settlement-and-evidence-profile.md`

Mark 2c-B written in §0a; record that `0x0031` is allocated and the market encoding blocker closed;
note that §6.3's `c_dsm_plus` row is superseded by ruling 1, and that §6.2's "the disclosure
decision already made and shipped" is corrected by ruling 4.

---

# Closure status

## Encoding closure — ACHIEVED for both shapes

```text
Owner close   complete, given prepared close_authorization bytes;
              the grammar to produce fresh ones is frozen here
Market        COMPLETE. 0x0033 field 6 nests 0x0031 schema 1.
              A conformant market b is constructible.
```

`0x000E` and `0x0033` leave A-stage. The registry's sole remaining encoding blocker is closed.

## Verification closure — NOT claimed

Open on `ValidDlvSuccessor`, immutable-addressing rules, P0–P6 authority-walk closure and the
`0x001B`–`0x0030` absorption — **all 2c-C**. `TA_B` `0x0011` and the bundle-acceptance leaf are
**2c-D**, and `TA_B`'s field table must be *re-derived* once the leaf authenticates `b`.

## Formal-model coverage — NOT claimed

No formal model governs this layer. Recorded rather than elided.

---

# Scope

**Documentation only. No Rust, no proto, no tests, no encoder.**

```text
This docs-only amendment does not add the 0x0031 class constant.
The first implementation change that implements 0x0031 MUST reserve the
class constant and add the collision test in the same change.
2c-C still owns the broader 0x001B-0x0030 namespace absorption audit.
```

Not 2c-B's: `ValidDlvSuccessor` and the `0x001B`–`0x0030` absorption (2c-C); `TA_B` `0x0011`,
`0x0032` and the bundle-acceptance leaf (2c-D). The four unvalidated operation fields are pinned by
the chain-tip conjunct but not *validated* — that is `ValidDlvSuccessor`, routed to 2c-C.

---

# Verification

1. **The A+B closure test.** Encode a complete market bundle from the field tables in 2c-A and this
   amendment. Achieved: the objects above were encoded from these tables and are byte-determined for
   the stated fixture. `same exact prepared candidate + same exact canonical recovery material ->
   identical B bytes -> identical b`.
2. **Namespace re-audit, run before writing.** Code tops out at `0x0030`; `0x0031`/`0x0032` appear
   in no Rust constant and no proto, and are claimed in prose for 2c-B and 2c-D. `0x0031` is free.
   *(Audit as run, 2026-09-09; the 2c-A.1 adopting change has since taken `0x0031` as
   `DSM_SUCCESSOR_EVIDENCE` and reserved `0x0032` for 2c-D, with the collision test that scope
   required.)*
3. **§2.8 audit.** Seven field numbers, all new within `0x0031`; no reuse; **no new burn** — this is
   a first ship at schema 1.
4. **Both byte grammars, encoded from these tables.** `CloseAuthorizationPreimageV1` signing form is
   150 bytes and its arithmetic closes independently
   (`1 + 36 + 36 + 8 + 36 + 8 + 8 + 8 + 4 + 4 + 1`); the cleared signature renders as
   `00 00 00 00`; the discriminator is `0x1c` = 28 and `mode` is `1`.
   **Owed at implementation:** byte-equality against a running `Operation::to_bytes` requires a test
   binary this docs-only change cannot add. The first commit implementing `0x0031` must assert it,
   and **if they differ, this amendment is wrong, not the code.**
5. **Encoding-level conjunct, hostile case.** An `operation_bytes` with trailing bytes after a valid
   decode, a wrong discriminator, or a short `sigma` — whose `trader_successor` was computed over
   those same bytes so the chain-tip equality passes — must be refused by the conjunct. Owed at
   implementation for the same reason as (4); the ordering in this amendment is what makes it
   possible.
6. **Self-contradiction sweep** — no sentence claims a `c_dsm_plus` field, claims the linkability
   disclosure is already shipped, says "sign `Operation::to_bytes`", says the owner-close shape was
   fully constructible under 2c-A alone, or claims `route_commit_bytes` is recoverable from `B`
   after the Route cut.
7. **Scope proof** — `git diff --stat` shows `docs/` only.
8. **Decision-record completeness** — all four rulings present with their rejected alternatives.
