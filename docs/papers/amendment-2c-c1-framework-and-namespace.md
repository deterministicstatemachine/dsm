# Amendment 2c-C1 — canonical framework and the economic namespace

Status: **ENCODING CLOSURE FOR THE ECONOMIC SUBSTRATE, EXCEPT `0x0028` (BLOCKED ON `0x002D`).
VERIFICATION CLOSURE IS 2c-C2/C3/C4's.** 2026-09-08.

Normative and encoder-free. First of the four sub-amendments fixed by
[`amendment-2c-c-verification-closure-decomposition.md`](amendment-2c-c-verification-closure-decomposition.md).
Governs registry classes `0x001B`–`0x0030` and the reserved block `0x002A`–`0x002F`.

## Context

Sixteen economic CCB classes ship in Rust and appear in **no** registry row. The registry claims to
be the single namespace, and §2.8 makes a class number permanent on first ship, so a namespace the
registry cannot see is a namespace that can be reallocated by accident. C1 closes that.

C1 is a prerequisite for C2, C3 and C4: each of them verifies over these objects, and none can
state a reproducible rule about an object whose bytes are defined only by a Rust encoder.

---

## One retraction, and a finding sharpened — corrections to documents already merged

### The economic burn finding stands. It is sharpened, not withdrawn.

An earlier draft of this amendment retracted the 2c-C decomposition's burn finding outright, calling
all three of its limbs false. **That retraction was itself false and is withdrawn.** It was written
against a working tree that a research subagent had silently modified mid-audit: the agent added the
two pairs to `schema::BURNED`, added an asserting test, and edited the registry's burned-schema
paragraph. A second audit pass then read that state and reported the defect as absent. Every claim
below is re-derived from a clean `origin/main` and, where it concerns runtime behaviour, **executed
rather than read**.

Limb by limb, the decomposition was right twice and wrong once:

```text
"absent from schema::BURNED"                      TRUE
"no test asserts the refusal"                     FALSE -- the test exists
"the registry burned-schema paragraph omits them" TRUE
```

Executed against a clean checkout:

```text
is_burned(0x0026, 1) = false
is_burned(0x0027, 1) = false
is_burned(0x0001, 1) = true      <- control: a burn that IS recorded

decode_credit_source(0x0026 schema-1 bytes) -> UnknownSchema { got: 1 }
decode_credit_source(0x0027 schema-1 bytes) -> UnknownSchema { got: 1 }
```

**The defect, stated precisely.** The burn is declared in prose and recorded in no table that
carries permanence. `ccb/mod.rs:111-114` declares it — *"schema 1 EXCEPT `0x0026`/`0x0027`, whose
schema 1 is BURNED (3.6, owner ruling 2026-08-28)"* — while `schema::BURNED` (`ccb/mod.rs:201-217`)
carries neither pair. `Cursor::envelope` (`ccb/decode.rs:124-131`) consults `is_burned` only after a
schema mismatch, so schema-1 bytes **are** refused — but as `UnknownSchema`, *a schema I do not
recognise*, rather than `BurnedSchema`, *a schema permanently retired*.

Two consequences, different in kind:

```text
decode safety     INTACT.  No schema-1 bytes are accepted on any path.
burn permanence   NOT RECORDED.  §2.8's never-re-assign rule is carried by
                  schema::BURNED, and that table does not know these two
                  numbers were ever spent.
```

The second is the live one. §2.8 makes a burn permanent, and `schema::BURNED` is the only
machine-readable statement of which schema numbers are spent. A future cut bumping `0x0026` to
schema 3 adds `(0x0026, 2)` to that table and finds no record that schema 1 was ever used.

**Why the existing test does not catch it.** `the_burned_dlv_source_schemas_are_refused`
(`dsm/tests/economic_provenance_wire.rs:486`) stamps schema 1 over canonical bytes and asserts
`decode_credit_source(&burned).is_err()`. `UnknownSchema` satisfies that assertion, so the test is
green under the defect and would stay green if the burn were never recorded at all. The
decomposition was wrong that no test exists; the test is nevertheless not evidence that the burn is
recorded, because it never reads the refusal's **reason**. An assertion that something fails is not
an assertion about why — the same error, at the level of a test, that produced the false retraction
at the level of an audit.

C1 owns the registry prose correction (below). The `schema::BURNED` entries, and a test that
discriminates `BurnedSchema` from `UnknownSchema`, belong to the first implementation change that
adopts this amendment — C1 is docs-only.

### §2 needs no new types

This is the one retraction that survives. The decomposition gives *"§2 framework extensions REQUIRED
before the economic classes can be expressed at all"* as one of three grounds for the four-way split.
That is too strong.

§5.2 `StorageSet` already establishes the mechanism: *"The element encoding is declared here, because
§2.4 does not cover it."* **A field table may declare an encoding the framework does not supply.**
That covers `0x001E` field 3's uncounted 256 × `digest32` without touching §2, and it covers every
other gap the audit surfaced.

The remaining two grounds for the split stand unchanged — ~26 open decisions, and four dimensions
that are separable in fact. This retraction narrows the reason, not the decision.

---

## Ruling A — one identity form: inner for semantics, outer only at the storage boundary

Two different layers were being conflated:

```text
canonical object / content identity     h    = H_dom(N, P)
storage addressing wrapper              addr = H_dom(DSM/storage-object, N ‖ h)
```

Six of the seven credit sources carry a content address. Four use the inner form; `0x0030`'s
`faucet_claim_evidence_addr` alone calls `immutable_addr` and carries the outer form. The manifest's
derived provenance-index list therefore mixes both, so two references to the *same* canonical object
can differ solely because one producer wrapped the identity for transport.

**Normative rule:**

> All provenance-index entries and all `*_addr` fields of the economic classes carry the canonical
> **inner** content identity `H_dom(N, P)`. The **outer** storage-object address
> `H_dom(DSM/storage-object, N ‖ H_dom(N, P))` is used only when interacting with the immutable
> storage layer. It is never the canonical provenance identifier.

A foreign verifier can then compute what a 32-byte digest means without consulting the field number.

**The schema-cut determination, made explicitly rather than assumed.** §2.8 requires a new schema
version for changed semantics of an **already-frozen** schema. `0x0030` schema 1 has never been
frozen *by the registry* — it ships in code and appears in no row. This is therefore a **first ship,
not a burn**, exactly the determination 2c-A made for `0x000E`: *"`0x000E` has never had a defined
schema-1 field table… this is a first ship, not a burn."* C1 defines `0x0030` schema 1 with the
inner form; no bump, no burned pair.

**Clean cut, no dual interpretation:**

```text
old 0x0030 outer-address value  !=  canonical C1 value
no accept-inner-or-outer, no inspect-and-guess, no fallback conversion
```

## Ruling B — `0x0028` is structurally frozen and beta-refused

`0x0028 CreditSourceVerifiedOfflineReentry` is unreachable in both directions: no
`CreditSourceFacts` variant exists, and the verifier returns `NotYetImplemented { class: 0x0028 }`.
Its field 4 addresses class `0x002D`, which is reserved with no field table, no domain tag and
**no defined preimage**.

It is absorbed with its shipped four-field layout, because leaving an already-allocated,
already-encoding class out of the registry recreates the exact split C1 exists to close. But its
registry status is **not** "defined":

```text
0x0028 namespace / field layout   FROZEN
0x0028 semantic usability          NOT CLOSED
0x0028 beta admission              REFUSED
blocking dependency                field 4 references 0x002D, whose canonical preimage
                                   is not yet defined
```

Its §3 status cell reads **STRUCTURALLY FROZEN — BLOCKED ON `0x002D` — BETA REFUSED**, so no later
implementer reads a complete-looking four-row table and assumes field 4 has a valid target. Burning
the number was rejected: the arm is deferred work, not an error, and §2.8 burns permanently.

## Ruling C — `0x0029` field 6 admits no zero

The class encodes `amount == 0` today, while the only consuming path refuses it — the `0x0023` arm
requires `op_amount > 0` and then `body.amount == op_amount`. A zero-amount authorization is
therefore encodable, signable, and incapable of ever funding a credit.

```text
0x0029 field 6 amount : u64
valid domain          : 1 ..= 2^64 - 1
amount == 0           : INVALID — a decoder/validator MUST refuse, a producer MUST NOT emit
```

This matches what `0x001F` field 2 already does, where zero means leaf-absent and has no canonical
bytes. `0x0023` keeps its own `op_amount > 0` check: the two are not redundant, because `0x0029`
answers *"what is a valid issuance authorization?"* and `0x0023` answers *"what is a valid credit,
and does this authorization match it?"* Both must independently exclude zero.

Any zero-valued `0x0029` object from pre-registry beta code is **not** grandfathered.

## Ruling D — every reserved number appears in the registry

`0x002A`–`0x002F` are allocated namespace states, not holes:

```text
RESERVED  !=  unallocated
RESERVED  !=  class
RESERVED  !=  burned
```

**Normative rule:**

> Every `u16` value protected by `ccb::reserved` MUST appear in the canonical namespace registry as
> reserved, including any named reservation purpose. Reserved entries receive no §5 object table and
> have no schema. Promotion of a reserved value into a class is a normative registry change and must
> be accompanied by the corresponding code change and collision test.

`0x002D` is **not** generically reserved — it is held for the class `0x0028` field 4 depends on, and
its row says so, so the reservation's purpose survives.

```text
§3 registry      normative allocation state
ccb::reserved    implementation enforcement of that state
§5               only actual object classes
```

---

# The sixteen field tables

All sixteen are **substrate**: allocated from the single namespace, carrying the same immutability
rules as `0x0018`–`0x001A`, and **excluded from §4's Rev 15 closure count**. Every table below was
read from `encode()` and independently cross-checked against the decoder in
`dsm/src/economic/decode.rs`, which is a second implementation written from the opposite side.

Fourteen ship at schema 1; `0x0026` and `0x0027` ship at **schema 2**, their schema 1 burned by the
peer economic-position cut — a burn that `schema::BURNED` and the registry do not yet record (above).

## §5.24 `EconomicRootClaimBody` — `0x001B`, schema 1

Signed. Per §2.9 the signature is **not** a field: it travels in the protobuf carrier
`EconomicRootClaimV1 { body_ccb, claimant_signature }`, over
`m = H_dom(DSM/economic-root-claim-sign/v1, CCB)`. Protobuf is carrier only — the signed preimage is
the domain hash of the CCB, never the transport bytes.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `trader_genesis` | `digest32` | |
| 2 | `trader_devid` | `digest32` | |
| 3 | `economic_position` | `u64` | |
| 4 | `post_economic_root` | `digest32` | |
| 5 | `admission_manifest_addr` | `digest32` | the only edge from a claim into its evidence DAG; equals `0x001C`'s inner identity |
| 6 | `root_register_storage_set_id` | `digest32` | a member of the **signed** body, not transport context — a claim cannot be replayed against a different register set |
| 7 | `signature_alg` | `u16` enum | must be a declared `signature_alg`; beta declares only `0x0001 SPHINCS_PLUS_SPX256F` |
| 8 | `claimant_public_key` | `bytes` | length must equal the declared algorithm's public-key length — 64 for `0x0001` |

242 bytes at `signature_alg = 0x0001`.

## §5.25 `EconomicAdmissionManifest` — `0x001C`, schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `authority_position` | `digest32` | a transition digest, never a counter |
| 2 | `transition_witness_addr` | `digest32` | inner identity of `0x001D` |
| 3 | `authority_evidence_addr` | `digest32` | |
| 4 | `substrate_dsm_successor` | optional `digest32` | **mutually exclusive with field 5** |
| 5 | `substrate_offline_boundary` | optional `digest32` | **mutually exclusive with field 4** |
| 6 | `provenance_evidence_addrs` | set of `digest32` | §2.4 count prefix; **sorted ascending by the raw 32 bytes**; duplicates invalid |

**The two-slot positional union, declared here because §2.3 speaks about one optional at a time and
says nothing across fields.** Both presence markers are always emitted, so field positions never
shift, and **exactly one** of fields 4 and 5 is present:

```text
DsmSuccessor     0x01 ‖ <32>   0x00
OfflineBoundary  0x00          0x01 ‖ <32>
both present     INVALID
neither present  INVALID
```

The two arms are byte-distinct at the same length. A decoder refuses any marker byte other than
`0x00`/`0x01`, and refuses both-present and neither-present.

138 + 32·n bytes.

## §5.26 `EconomicTransitionWitness` — `0x001D`, schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `pre_economic_root` | `digest32` | |
| 2 | `post_economic_root` | `digest32` | must equal the root the mutations derive |
| 3 | `economic_operation_id` | `digest32` | |
| 4 | `operation_digest` | `digest32` | binds the witness to the local acceptance |
| 5 | `mutations` | sequence of nested `0x001E` | §2.5 count prefix; **count ≥ 1** |
| 6 | `credit_sources` | sequence of nested union `{0x0023, 0x0024, 0x0025, 0x0026 s2, 0x0027 s2, 0x0028, 0x0030}` | §2.5 count prefix; **strictly ascending by the element's `credit_mutation_index`** |

**Field 6's ordering predicate is declared here, because §2.4 cannot state it.** §2.4 orders a set
ascending by `enc(e)`, and `enc(e)` for a credit source begins `u16 class ‖ u16 schema`, so
`enc(e)` order is *(class, schema, index…)* — which differs from index order whenever two elements
have different classes. Field 6 is therefore a §2.5 **sequence** whose order is constrained by this
table rather than by the framework: strictly ascending `credit_mutation_index`, which also forbids
duplicates without needing set semantics.

**Field 6's element type is a union of seven classes**, discriminated by the §2.1 envelope exactly
as §2.5's heterogeneous-sequence rule intends — no in-band tag.

## §5.27 `EconomicLeafMutation` — `0x001E`, schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `pre_state` | optional nested union `{0x001F, 0x0020, 0x0021, 0x0022}` | |
| 2 | `post_state` | optional nested union `{0x001F, 0x0020, 0x0021, 0x0022}` | **not both absent** |
| 3 | `siblings` | **exactly 256 × `digest32`, no count prefix** — 8192 raw bytes | declared here; see below |

The three legal combinations are *(absent, present)* insert, *(present, present)* update, and
*(present, absent)* delete. Where both are present their **position material must agree** — the
class and identifying digests of a leaf cannot change under a mutation of that leaf.

**Field 3's encoding is declared here, because §2.2 has no array type and both §2.4 and §2.5
mandate a `u32_BE` count.** The count is not carried because it is not free: it is fixed at
`ECONOMIC_SMT_HEIGHT = 256` by the tree the proof is against. Emitting it would be a second,
settable statement of a constant — the alias pattern this registry removes. A decoder reads exactly
256 digests and never reads a count; any other length is invalid. This is the same in-table
mechanism §5.2 uses for its tuple element, and it needs no §2 change.

## §5.28–§5.31 the leaf states — `0x001F`–`0x0022`, all schema 1

All four are envelope + scalars: no optionals, no sets, no sequences, no nesting.

**`0x001F EconomicBalanceState`** — 44 bytes

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `policy_commit` | `digest32` | |
| 2 | `amount` | `u64` | **must be non-zero** — enforced in both the constructor and the encoder |

**`0x0020 EconomicVaultReserveState`** — 84 bytes

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `vault_id` | `digest32` | |
| 2 | `policy_commit` | `digest32` | |
| 3 | `amount` | `u64` | **zero is legal and meaningful** — the terminal drained-vault state |
| 4 | `vault_sequence` | `u64` | |

**The `0x001F`/`0x0020` zero asymmetry is real and load-bearing, and the registry states it rather
than normalising it.** A zero *balance* is leaf-**absent**: it has no canonical bytes, so encoding
one would create a second representation of absence. A zero *reserve* is leaf-**present** at a
stated `vault_sequence`: it is the terminal state of a closed vault, and erasing it would erase the
fact that the vault was drained rather than never funded.

**`0x0021 EconomicSettlementReceiptState`** — 196 bytes

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `vault_id` | `digest32` | |
| 2 | `receipt_id` | `digest32` | **derived, not chosen** — must equal `derive_receipt_id(vault_id, x)` |
| 3 | `x` | `digest32` | |
| 4 | `parent_sequence` | `u64` | |
| 5 | `new_sequence` | `u64` | must equal `parent_sequence + 1` |
| 6 | `input_policy_commit` | `digest32` | **must differ from field 8** |
| 7 | `input_amount` | `u64` | must be non-zero |
| 8 | `output_policy_commit` | `digest32` | **must differ from field 6** |
| 9 | `output_amount` | `u64` | must be non-zero |

**`0x0022 EconomicConsumedSourceState`** — 68 bytes

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `source_id` | `digest32` | |
| 2 | `consumer_economic_operation_id` | `digest32` | attribution — what turns a bare "spent" flag into a statement of *who* spent it |

## §5.32 `IssuanceAuthorizationBody` — `0x0029`, schema 1

148 bytes.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `policy_commit` | `digest32` | |
| 2 | `issuer_genesis` | `digest32` | |
| 3 | `issuer_devid` | `digest32` | |
| 4 | `issuer_economic_position` | `u64` | |
| 5 | `recipient_operation_digest` | `digest32` | |
| 6 | `amount` | `u64` | **valid domain `1 ..= 2^64 − 1`; zero is invalid** (ruling C) |

## §5.33–§5.39 the credit sources — `0x0023`–`0x0028`, `0x0030`

Seven arms, discriminated by the §2.1 envelope class — there is no in-band tag. Field 1 of every
arm is `credit_mutation_index : u32`, the index into the enclosing witness's `mutations` sequence,
and the enclosing `0x001D` field 6 requires those indices to be strictly ascending across the
sequence.

Every `*_addr` field below carries the **inner** identity `H_dom(N, P)` per ruling A.

**`0x0023 CreditSourceAuthorizedIssuance`** — schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `credit_mutation_index` | `u32` | |
| 2 | `issuance_authorization_addr` | `digest32` | addresses `0x0029` |

**`0x0024 CreditSourceSameTransitionMove`** — schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `credit_mutation_index` | `u32` | **must differ from field 2** |
| 2 | `debit_mutation_index` | `u32` | a transition cannot fund itself from itself |

**`0x0025 CreditSourceValidatedPeerDebit`** — schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `credit_mutation_index` | `u32` | |
| 2 | `peer_genesis` | `digest32` | |
| 3 | `peer_devid` | `digest32` | |
| 4 | `peer_economic_position` | `u64` | **untrusted locator** — the verifier derives the position independently |
| 5 | `peer_debit_mutation_index` | `u32` | indexes the **peer's** witness, not this one |
| 6 | `acceptance_evidence_addr` | `digest32` | |

**`0x0026 CreditSourceDlvReserveConsumption`** — **schema 2** (schema 1 burned)

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `credit_mutation_index` | `u32` | |
| 2 | `vault_id` | `digest32` | |
| 3 | `parent_sequence` | `u64` | |
| 4 | `x` | `digest32` | |
| 5 | `owner_economic_position` | `u64` | **the schema-2 field** — an untrusted locator |
| 6 | `reserve_consumption_evidence_addr` | `digest32` | |

**`0x0027 CreditSourceValidatedDlvSettlementPayment`** — **schema 2** (schema 1 burned)

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `credit_mutation_index` | `u32` | |
| 2 | `vault_id` | `digest32` | |
| 3 | `settlement_receipt_id` | `digest32` | |
| 4 | `parent_sequence` | `u64` | |
| 5 | `trader_genesis` | `digest32` | |
| 6 | `trader_devid` | `digest32` | |
| 7 | `trader_economic_position` | `u64` | **the schema-2 field** — an untrusted locator |
| 8 | `payment_evidence_addr` | `digest32` | |

**`0x0028 CreditSourceVerifiedOfflineReentry`** — schema 1 — **STRUCTURALLY FROZEN, BETA REFUSED**

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `credit_mutation_index` | `u32` | |
| 2 | `prior_boundary_id` | `digest32` | **must differ from field 3** |
| 3 | `unload_boundary_id` | `digest32` | |
| 4 | `branch_evidence_addr` | `digest32` | **no defined preimage** — addresses reserved class `0x002D`; see ruling B |

**`0x0030 CreditSourceValidatedFaucetDistribution`** — schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `credit_mutation_index` | `u32` | |
| 2 | `faucet_id` | `digest32` | must equal the derived canonical faucet identity |
| 3 | `ticket_index` | `u64` | |
| 4 | `faucet_claim_evidence_addr` | `digest32` | **inner form per ruling A** — the shipped code emits the outer form and must change |

**Two schema-2 arms, one reason.** Both `0x0026` and `0x0027` carry a peer/owner
`*_economic_position` that schema 1 did not, and both are labelled **untrusted locators**: they say
where to start looking, never what is true. The verifier derives the position independently. That is
the same locator-not-authority distinction 2c-A applied to `trader_parent`.

---

# The identity cuts

Ruling A and decomposition ruling 2 together require these derivations to change. Each is a **clean
beta cut** — no dual resolver, no fallback, no accept-either-encoding.

| Object | Today | After |
|---|---|---|
| `0x0030` field 4 target | outer `addr(N, P)` | inner `H_dom(N, P)` |
| economic register-cell identity | prost bytes | a frozen CCB representation |
| quorum comparison operand | prost bytes | canonical CCB bytes, or a digest derived from them |
| `AuthorityEvidenceV1` content address | `H(prost_bytes)` | `H_dom(domain, CCB(...))` |

**A CCB identity does not always mean a new class.** Per decomposition ruling 2, C1 uses the
smallest representation that fits: an object with independent identity and addressing gets a
registered class; a canonical operand contained entirely within another registered object gets its
encoding defined there. What is never permitted is prost bytes as the normative identity.

**The transitive cut, enumerated rather than avoided.** Re-basing an evidence address changes the
`0x001C` manifest that commits it, hence the manifest's own identity, hence the signed `0x001B`
body's field 5. Both enclosing objects keep the same canonical types and the same meanings —
content addresses of the referenced objects — so **no schema bump of `0x001C` or `0x001B` is
required**, on the same reasoning 2c-B ruling 3 applied. Existing prost-addressed artifacts are not
migrated.

---

# Registry edits

- **§3** — add sixteen class rows (`0x001B`–`0x0030`), each marked **substrate**, plus six
  **RESERVED** rows for `0x002A`–`0x002F` per ruling D, with `0x002D`'s row naming its reservation
  purpose: held for the class `0x0028` field 4 depends on.
- **§5.24–§5.39** — the field tables above.
- **§4** — the counts are unchanged: all sixteen are substrate and excluded from the Rev 15 closure
  count, exactly as `0x0018`–`0x001A` and `0x0031` are. Add a sentence saying so, so a reader does
  not expect the total to move.
- **§2.8** — record ruling D's rule that every `ccb::reserved` value must appear in §3.
- **No new §2 primitives.** Every gap is closed by an in-table declaration under §5.2's precedent.

# Closure status

**Encoding closure — ACHIEVED for fifteen of sixteen.** `0x0028` is structurally frozen and beta-
refused, blocked on `0x002D`.

**Verification closure — NOT claimed, and not C1's.** What each of these objects *means* to a
verifier is C2's (the algorithms), C3's (`ValidDlvSuccessor`) and C4's (the walk). C1 fixes only
what their bytes are.

**Formal-model coverage — not claimed.**

# Scope

**Documentation only.** The implementation change that adopts ruling A's inner form, ruling C's
non-zero domain, and the identity cuts is owed separately, and it must carry the conformance vectors
named below.

# Verification

1. **Every field table was read from `encode()` and cross-checked against the independent decoder**
   in `dsm/src/economic/decode.rs`, which is a second implementation written from the opposite
   side. Field counts, order and primitive types agree in all sixteen.
2. **Schema constants read from each `impl CcbObject` directly** — fourteen at 1, `0x0026` and
   `0x0027` at 2.
3. **§2.8 audit** — sixteen first ships; no number is reused. The only burns in this block are
   `(0x0026, 1)` and `(0x0027, 1)`, and the registry rows added here are the first place either is
   written down — `schema::BURNED` still does not carry them.
4. **A gap this audit found and C1 does not close.** `0x001B`–`0x001E` have **no independent-encoder
   conformance test** and no row in `live_schemas_match_the_registry_and_none_is_burned`, so the
   layouts frozen here are pinned by nothing but the encoder/decoder pair. The implementation change
   that adopts C1 must add a conformance vector per class — otherwise §2.8 freezes a layout that no
   test defends.
5. **Every claim about the burn re-derived from a clean `origin/main` and executed**, not read:
   `is_burned` for both pairs plus a recorded-burn control, and the actual `DecodeError` variant
   returned for schema-1 bytes. The §2 retraction rests on §5.2's in-table precedent, a documentary
   fact. This bullet previously asserted that both retractions were verified from source; one of
   them had been verified against a tree a subagent was concurrently writing to.
