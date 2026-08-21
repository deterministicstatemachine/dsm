# CCB Object Registry — canonical cross-implementation commitment encoding

Normative companion to SoFi Revision 15 (`.github/instructions/sofispecs.instructions.md`).
Establishes the CCB framework and object registry for finding 7 of
`docs/reports/2026-08-21-rev15-conformance-delta.md`. **Finding 7 remains OPEN.**

This document supplies the framework, the namespace and a complete gap inventory. It does not
make Rev 15's commitments independently derivable, because ten of nineteen object classes
still have no contents in the specification — see §4 and §6. Finding 7 closes when those are
resolved by the normative amendments listed in §7, not when this document merges.

This document is **normative and encoder-free**. It contains no Rust, no reference
implementation and no golden vectors, by design. Its single reviewable question is *are these
bytes uniquely specified?* — whether an implementation emits them is a separate question,
answered by the encoder work that follows. A reference encoder must never define the protocol
by accident, so the schema is fixed here first and the encoder is written from this text.

**Terminology.** This is canonical **cross-implementation commitment encoding**. It is not
consensus encoding: DSM has no global consensus layer, and the term would import a model the
protocol does not have. What is at stake is whether two independent implementations derive
identical bytes, and therefore identical commitments, from the same logical object.

## 1. Why this exists

Req 3.1 states the CCB rules — fixed-width big-endian integers, 4-byte length-prefixed byte
strings, "fields emitted in ascending declared field-number order", explicit absence markers,
sets sorted lexicographically by element CCB, sorted maps, no floating point, and "every CCB
blob begins with an object-class discriminant and CCB schema version". Req 3.2 requires that
no two logical objects share an encoding and no logical object has two.

Revision 15 never supplies the metadata those rules consume:

- No field number is declared for any object. The phrase `declared field` occurs exactly once
  in the specification, inside rule 3 itself.
- No object-class discriminant and no CCB schema version ever takes a value.
- The document contains two width mentions in total: the 4-byte length prefix, and one
  `32-byte`.

`Canon(...)` is invoked in nineteen places across roughly fifteen object classes and defined
in none of them. `c_n`, the fulfillment mechanism `M`, `storage_set_id`, the acceptance digest
`a_B` and the Definition 6.17 settlement resource key are therefore not derivable from the
specification alone.

That gap is not hypothetical. `storage_set_id = H(DSM/storage-set ‖ Canon(S))` ships today
with a layout chosen only in Rust, and the storage node agrees with the client because it
calls the client's helper directly. Agreement by shared code is implementation monoculture,
and it ends the moment a second implementation exists. §5 of this document absorbs that
layout as written rather than changing it.

## 2. Framework

### 2.1 Blob envelope

Every CCB blob is:

```
CCB(o) = u16_be(object_class) ‖ u16_be(schema_version) ‖ field_1 ‖ field_2 ‖ … ‖ field_k
```

Fields are emitted in ascending declared field number with no gaps, no tags and no lengths
other than those the field type specifies. The encoding is not self-describing: a decoder
recovers structure from `(object_class, schema_version)` and this registry, never from the
byte stream.

There is no terminator and no total-length prefix. A CCB blob is consumed in the context that
produced it — as a hash preimage, as signed bytes, or nested inside an enclosing CCB whose
field table fixes its position.

### 2.2 Primitive encodings

| Type | Encoding |
|---|---|
| `u8`, `u16`, `u32`, `u64` | fixed-width big-endian, no varints |
| `bool` | `u8`, exactly `0x00` false or `0x01` true; any other byte is invalid |
| `bytes` | `u32_be(len)` ‖ raw bytes |
| `digest32` | exactly 32 raw bytes, **no length prefix** — the width is fixed by the type |
| `string` | UTF-8, NFC-normalized, encoded as `bytes` |
| enumerations | `u16_be` over values declared in this registry |

Floating point is forbidden. Signed integers are forbidden; a quantity that can be negative is
modelled as a sign field plus a magnitude, declared explicitly in the object's field table.

`digest32` is deliberately distinct from `bytes`. A 32-byte digest emitted as `bytes` would
carry a redundant length prefix that a second implementation might reasonably omit, which is
exactly the class of divergence Req 3.2 forbids.

### 2.3 Optional fields

An optional field is a presence marker followed by the value when present:

```
absent:  0x00
present: 0x01 ‖ <value in its declared type>
```

The marker is always emitted. An absent optional field is never skipped, because skipping
would make two distinct logical objects — one with the field absent, one with the following
field shifted — share a byte string.

### 2.4 Sets

```
set = u32_be(count) ‖ enc(e_1) ‖ enc(e_2) ‖ … ‖ enc(e_count)
```

`enc(e)` is the element's declared encoding: the complete `CCB(e)` when the element type is an
object class, or the primitive encoding of §2.2 when it is a primitive such as `digest32`. A
set's field table declares which. Primitives are not wrapped in an envelope, because a
primitive has no object class to discriminate.

Elements are sorted **ascending lexicographically by `enc(e)`**, compared as unsigned byte
strings, shorter-is-smaller on a prefix tie. Duplicate elements — equal `enc(e)` — are
invalid, not deduplicated: a producer emitting a duplicate has a bug, and silently collapsing
it would let two logical objects share an encoding.

The count is part of the preimage. Without it, a set of variable-length elements could be
re-split, so `{"ab", "c"}` and `{"a", "bc"}` would collide.

### 2.5 Maps

```
map = u32_be(count) ‖ (CCB(k_1) ‖ CCB(v_1)) ‖ … ‖ (CCB(k_count) ‖ CCB(v_count))
```

Pairs are sorted ascending by key CCB under the same comparison as §2.4. Duplicate keys are
invalid.

### 2.6 Nested objects

A nested object is emitted **inline, by value, as its complete CCB including its own
discriminant and schema version**. It is not replaced by a digest.

Emitting a sub-object as a digest is permitted only where the enclosing object's field table
declares a `digest32` field whose domain is named in that table — for example `c_0` inside the
fulfillment mechanism `M` of class `0x0006`, which the specification itself defines as a
commitment rather than as an inlined state. Substituting a digest for a declared nested object, or inlining an
object where a digest is declared, is invalid.

This rule exists because "sub-object by digest" relocates ambiguity rather than removing it.
A digest is only well-defined once the preimage is, so a registry that inserted policies by
digest without defining the policies would leave the same hole one layer down.

### 2.7 The discriminant and field-number namespace

Object classes are assigned from the single table in §3. Field numbers are assigned per object
class in that object's field table. Neither is assigned ad hoc in prose.

**Immutability.** Once an `(object_class, schema_version)` pair ships, its discriminant and
every field number within it are frozen:

- A field number is never reused for different semantics within a schema version.
- A field is never removed or renumbered within a schema version.
- Changed semantics require a **new schema version** for that object class, or a **new object
  class** if the object's identity changes.
- A retired object class is never re-assigned; its number is burned.

Without this rule the registry becomes the next source of the ambiguity it exists to close: a
recycled number makes two logical objects share an encoding across releases, which is Req
3.2's failure in slow motion.

**Reserved ranges.** `0x0000` is reserved and never assigned, so an all-zero buffer is not a
valid CCB blob. `0xFF00`–`0xFFFF` are reserved for experimental and test object classes and
must never appear in a production commitment.

### 2.8 Relationship to transport

CCB is not protobuf. Req 3.1 states this directly, and Req 3.3 keeps protobuf as the transport
encoding. A protobuf message may carry an object whose commitment is computed over its CCB,
but a serialized protobuf message is never a valid CCB blob and must never be hashed or signed
as if it were. Protobuf field numbers and CCB field numbers are independent namespaces and
need not agree.

## 3. Object-class registry

The single namespace. Every canonical object in Revision 15 that feeds a hash, a signature, a
storage address, a resource key or an authority check appears here.

| Class | Object | Schema | Commitment it feeds | Status |
|---|---|---|---|---|
| `0x0001` | `VaultStateV2` (`V_n`) | 1 | `c_n = H(DSM/vault-state ‖ CCB)` | **§5.1 — blocked, see §6** |
| `0x0002` | `StorageSet` (`S`) | 1 | `storage_set_id = H(DSM/storage-set ‖ CCB)` | §5.2 defined |
| `0x0004` | `EncumbranceClaim` (`e_j`) | 1 | `e_j = H(DSM/enc-claim ‖ …)` | §5.3 defined |
| `0x0005` | `EncumbranceSet` (`{e_j}`) | 1 | `E = H(DSM/enc ‖ vault_id ‖ CCB)` | §5.3 defined |
| `0x0006` | `FulfillmentMechanism` (`M`) | 1 | `M = H(DSM/fulfillment ‖ vault_id ‖ c_0 ‖ CCB(B_M))`, signed as `CCB(M)` | **partial — §6** |
| `0x0007` | `MarketPolicy` (`P_M`) | 1 | nested in `0x0001` | §5.7 defined |
| `0x0008` | `MarketBounds` (`B_M`) | 1 | nested in `0x0006` | §5.6 defined |
| `0x0009` | `ReleasePolicy` (`P_R`) | 1 | nested in `0x0001` | **blocked, see §6** |
| `0x000A` | `FeePolicy` (`Φ`) | 1 | nested in `0x0001` | §5.9 defined |
| `0x000B` | `TradeIntent` | 1 | `I = H(DSM/intent ‖ CCB)` | §5.5 defined |
| `0x000C` | `RouteSet` (`R`) | 1 | `X = H(DSM/route-set ‖ I ‖ CCB ‖ …)` | **blocked, see §6** |
| `0x000D` | `Route` (`r_i`) | 1 | set element of `0x000C` | **blocked, see §6** |
| `0x000E` | `SettlementBundle` (`B`) | 1 | `b = H(DSM/settlement-bundle ‖ CCB)` | §5.6 partial |
| `0x000F` | `ConsumedDlvTransition` (`T_v`) | 1 | nested in `0x000E` | §5.6 partial |
| `0x0010` | `DlvProofMaterial` (`P_v`) | 1 | nested in `0x000E` | **blocked, see §6** |
| `0x0011` | `TraderAcceptance` (`A_B`) | 1 | `a_B = H(DSM/trader-settlement-acceptance/v2 ‖ CCB)` | §5.7 partial |
| `0x0012` | `TradeDigest` | 1 | `d = H(DSM/digest ‖ CCB)` | **blocked, see §6** |
| `0x0013` | `ReferenceWindow` (`{d_i}`) | 1 | `W = H(DSM/ref-window ‖ pair_id ‖ CCB)` | §5.8 defined |
| `0x0014` | `ExternalCommitmentBody` (`X`) | 1 | `ExtCommit(X) = H(DSM/ext ‖ CCB)` | **blocked, see §6** |

`0x0000` reserved. `0x0003` is **burned**: it was briefly assigned to a `StorageMemberId`
object class before §5.2 established that member ids are bare length-prefixed bytes inside a
frozen layout, with no envelope and therefore no class. Per §2.7 a retired class number is
never re-assigned. `0xFF00`–`0xFFFF` reserved for test classes.

## 4. Status of this registry

**This first registry PR does not complete every field table, and says so rather than
inventing the missing ones.**

Of the nineteen live object classes above:

- **8 are fully specified** in §5 — `0x0002`, `0x0004`, `0x0005`, `0x0007`, `0x0008`,
  `0x000A`, `0x000B`, `0x0013`.
- **4 are partial** — `0x0006`, `0x000E`, `0x000F`, `0x0011` — where the specification fixes
  the field order or names the members but leaves types or a nested class open.
- **7 are blocked** with only a class assignment.

The blocked ones are blocked because the specification names them without ever enumerating
their contents: `P_M` is "the bounded market-fulfillment policy" and nothing more. Writing a
field table for those would settle protocol in this document exactly as writing an encoder
first would settle it in Rust. §6 states precisely what each one needs.

The framework in §2 and the namespace in §3 are complete and are **not** blocked on §6. They
can be reviewed, merged, and implemented against for the eight specified objects immediately.

## 5. Field tables

*(Sections 5.1–5.8 follow the framework above. Objects marked blocked in §3 carry only their
class assignment until §6 is resolved.)*

### 5.2 `StorageSet` — class `0x0002`, schema 1

**Absorbs the shipping layout without change.** `sdk/storage_set.rs` computes

```
storage_set_id = H(TAG_DSM_STORAGE_SET_V1 ‖ 0x00 ‖ u32_be(count)
                   ‖ for each id in lexicographic byte order: u32_be(len(id)) ‖ id)
```

and the storage node derives the same value through the same helper. Every deployed vault's
signed anchor already commits an id under this construction, so changing it would invalidate
them. The registry therefore adopts it as the normative encoding of `Canon(S)` rather than
replacing it.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `members` | set of `bytes` | ordered and encoded as spelled out below, **not** by §2.4 |

`members` is a set of UTF-8 member identity strings, each emitted as a bare `u32_be(len) ‖ id`
with no object envelope. Ordering is ascending lexicographic over the **raw id bytes**, which
for this frozen layout is the same as ordering over the emitted element bytes only because
every element carries an equal-width length prefix. An empty id, a duplicate id and an empty
set are each invalid.

**Two deliberate deviations from the framework, recorded rather than hidden.**

1. The §2.1 envelope is *not* prepended. The shipping preimage begins with the domain tag and
   a `0x00` separator — the output of `dsm_domain_hasher` — where a conformant object would
   begin with `u16_be(class) ‖ u16_be(version)`.
2. Elements are bare length-prefixed bytes rather than the `enc(e)` of §2.4, and there is no
   `StorageMemberId` object class. Class `0x0003` was briefly assigned to one and is burned.

Both deviations exist because every deployed vault's signed anchor already commits a
`storage_set_id` under this construction, and adopting the framework would invalidate all of
them. This class is frozen as shipped. A future `StorageSetV2` under a new class number may
adopt the standard envelope; **this one must not be "cleaned up".**

### 5.3 `EncumbranceClaim` — class `0x0004`, schema 1

The specification fixes the preimage directly:
`e_j = H(DSM/enc-claim ‖ vault_id ‖ p ‖ claim_seq ‖ amount ‖ token ‖ purpose)`.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `vault_id` | `digest32` | |
| 2 | `parent_state_commitment` | `digest32` | the `p` of the claim, per Def 4.1 `h_n` |
| 3 | `claim_seq` | `u64` | |
| 4 | `amount` | `u64` | base units; §3.4 fixed-point applies to derived ratios, not to this field |
| 5 | `token` | `digest32` | token policy commitment |
| 6 | `purpose` | `u16` | enumeration; values are declared where the purpose set is defined |

`EncumbranceSet` — class `0x0005`, schema 1 — is a set of `EncumbranceClaim` under §2.4.

### 5.5 `TradeIntent` — class `0x000B`, schema 1

The specification enumerates the members:
`TradeIntent = {token_in, amount_in, token_out, min_out, max_fee, max_hops, max_fanout, k, nonce}`,
and states that no expiry, timestamp or duration is permitted.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `token_in` | `digest32` | token policy commitment |
| 2 | `amount_in` | `u64` | base units |
| 3 | `token_out` | `digest32` | |
| 4 | `min_out` | `u64` | base units |
| 5 | `max_fee` | `u64` | base units |
| 6 | `max_hops` | `u32` | |
| 7 | `max_fanout` | `u32` | Req 9.1: bounds DLVs inside one same-pair allocation leg |
| 8 | `k` | `u32` | Req 9.1: bounds alternative routes retained in `R`; independent of field 7 |
| 9 | `nonce` | `digest32` | |

No field 10. Adding expiry or any time-like field to this class is forbidden; §9.1 of the
specification excludes them, and §2.7 forbids extending a shipped schema version.

### 5.6 `MarketBounds` — class `0x0008`, schema 1

Narrowed by the Def 5.2 amendments to the bounds with no home in `V_n` and none in the predicate
family. The invariant is **not** a field here: `P_M.family_id` names it, and a second
representation would be an alias.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `per_transition_size_ceiling` | `u64` | base units of the input leg; the market size bound of §5.1 together with the remaining reserves in `V_n` |
| 2 | `authorized_encumbrance_purposes` | set of `u16` | purpose enumeration; §2.4 ordering over the 2-byte encodings; empty set permitted and means no purpose is authorized |

### 5.7 `MarketPolicy` — class `0x0007`, schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `family_id` | `u16` | `0x0001` = `CONSTANT_PRODUCT_EXACT_INPUT`. Beta declares no other member |
| 2 | `family_version` | `u16` | `1` for beta. Fixes the pricing rule, the admissibility conditions and the evaluation budget together |
| 3 | `token_a_policy_commit` | `digest32` | strictly less than field 4 under unsigned lexicographic byte comparison |
| 4 | `token_b_policy_commit` | `digest32` | |

`evaluation_budget` is **not** a field. It is a constant of `family_version`, so an owner cannot
configure it and two implementations cannot agree on the bytes while disagreeing on whether
evaluation exhausted its allowance.

The fee is not a field either. `Φ` is the single authoritative fee policy and is a member of
`V_n`; carrying it here as well would be the alias the Def 5.2 amendment removed.

Ordering of fields 3 and 4 is a validity condition, not a normalization: an encoder must reject
an unordered or equal pair rather than swap it, because swapping would make two distinct logical
inputs produce one encoding.

### 5.8 `ReferenceWindow` — class `0x0013`, schema 1

`W = H(DSM/ref-window ‖ pair_id ‖ Canon({d_i}))`. The canonical object is the digest set;
`pair_id` is a sibling of the set in the `W` preimage, not a member of this object.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `digests` | set of `digest32` | §2.4 ordering over the raw 32-byte values |

A set of `digest32` sorts by the 32 raw bytes; there is no element envelope, because
`digest32` is a primitive rather than an object class.

### 5.9 `FeePolicy` — class `0x000A`, schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `fee_bps` | `u32` | `0 ≤ fee_bps < 10_000`; the exact rational `fee_bps / 10_000` under the §3.4 allowance |

`10_000` and above is invalid rather than meaningful — it would leave the pricing rule with a
zero or negative effective numerator. The width is 32 bits because that is the representation
already in use; re-scaling to Q32.32 would change every committed fee without changing any fee.

## 6. Blocked objects — what each one needs

These object classes are assigned but cannot be given field tables from Revision 15 as
written. Each entry states the exact missing decision. **None of them should be resolved by
writing an encoder.**

| Class | Object | What the specification says | What is missing |
|---|---|---|---|
| `0x0001` | `VaultStateV2` | the fifteen-member tuple of Def 4.1 | widths and types for every scalar; how `P_M`, `P_R`, `Φ`, `E` enter; `β`'s optional encoding. Blocked transitively on `0x0007`–`0x000A` |
| `0x0009` | `ReleasePolicy` `P_R` | "the bounded release/withdraw/close policy", owner-local per Req 4.6 | the entire contents |
| `0x000C` | `RouteSet` `R` | "`R = {r_1,…,r_k}`, canonicalized by route CCB ascending" | the route CCB it is ordered by — i.e. class `0x000D` |
| `0x000D` | `Route` `r_i` | referenced only as a set member | the entire contents |
| `0x0010` | `DlvProofMaterial` `P_v` | "proof material required to verify and later compose that DLV continuation" | the entire contents; likely a witness family rather than a flat record |
| `0x0012` | `TradeDigest` | commits "the pair, executed amounts, participating vault identifiers, parent bindings, fees, and `X`" | six named components with no types and no ordering for the multi-valued ones |
| `0x0014` | `ExternalCommitmentBody` `X` | `ExtCommit(X) = H(DSM/ext ‖ Canon(X))` | the entire contents |

Two of these have partial tables in §5 rather than none:

- `0x0006` `FulfillmentMechanism` is fixed as a preimage —
  `M = H(DSM/fulfillment ‖ vault_id ‖ c_0 ‖ CCB(B_M))` — so its field order is known and only
  `0x0008` blocks it. `Canon(P_M)` was removed from this preimage by the Def 5.2 amendment:
  `P_M` is a member of `V_0` and `c_0` commits the complete canonical `V_0`, so the mechanism
  already committed it transitively and the second copy was an alias, not a binding.
- `0x000E` `SettlementBundle` and `0x000F` `ConsumedDlvTransition` have their members named by
  Def 6.14 and the prose that follows it, and block on the types of those members plus
  `0x0010`.
- `0x0011` `TraderAcceptance` blocks on the encoding of `(C_T^+, σ_T^+)`, which is ordinary DSM
  successor material rather than a SoFi object, and therefore needs a decision about whether
  the DSM core encoding is referenced or restated.

## 7. What follows this document

In order, and not combined:

1. **This registry**, reviewed on the single question *are these bytes uniquely specified?*
2. **Resolution of §6 as three semantic amendments**, not one omnibus, ordered by dependency:

   **2a. DLV state and policy profile.** `VaultStateV2` `0x0001`, `MarketPolicy` `0x0007`,
   `MarketBounds` `0x0008`, `ReleasePolicy` `0x0009`, `FeePolicy` `0x000A`, and finishing
   `FulfillmentMechanism` `0x0006`. First, because it is what unblocks Anchor V2.

   Keep the beta policy family **intentionally narrow**. SoFi beta supports constant-product
   DLV market execution and owner-local full close; specify those actual profiles. `P_M` and
   `P_R` being abstract names is not a reason to design a generalized predicate VM — that can
   take new object or schema versions later, which is exactly what §2.7 provides for.

   The existing Rust `FulfillmentMechanism` enum spans Payment, CryptoCondition,
   MultiSignature, StateReference, RandomWalk, Bitcoin HTLC, AND/OR and AMM constant product.
   That is a legacy DLV mechanism family, and its breadth is **not** evidence that those
   variants belong inside a Rev 15 `P_M`. Preserve the intentional AMM facts — canonical
   token-policy identities, constant-product semantics, fixed fee representation, and actual
   reserves living outside the predicate — and design the normative objects from Rev 15's beta
   semantics rather than canonizing the enum.

   **2b. Routing and commitment profile.** `Route` `0x000D`, `RouteSet` `0x000C`,
   `ExternalCommitmentBody` `0x0014`, `TradeDigest` `0x0012`. One dependency cluster:
   `RouteSet` cannot be canonical until `Route` is, the digest binds `X`, and route ranking
   and membership need one byte identity. Existing route SDK and proto structures are evidence
   of current behaviour; only fields implementing already-approved Rev 15 semantics survive.
   An accidental transport field must not become canonical merely because it exists in
   protobuf.

   **2c. Settlement and evidence profile.** `DlvProofMaterial` `0x0010`, finishing
   `ConsumedDlvTransition` `0x000F`, `SettlementBundle` `0x000E`, `TraderAcceptance` `0x0011`.
   Needs the route and bundle identity from 2b. `TraderAcceptance` derives from Rev 15, not
   from the current receipt object — the bespoke `post_root` receipt is the thing being
   replaced.

   **Prerequisite inside 2c.** `A_B` carries ordinary DSM successor material
   `(C_T^+, σ_T^+)`. The repository's `CanonicalEncode` trait is described as the single
   source of truth for cryptographic commitments, but it only requires deterministic bytes
   per implementation; it is not a cross-implementation normative byte schema. If ordinary
   DSM successor CCB is not normatively specified elsewhere, it must be opened as a **Core
   canonical-successor encoding prerequisite** and referenced from SoFi — never restated ad
   hoc inside a SoFi amendment.

### Deriving from Rust versus designing fresh

A strict three-tier rule applies to every field in every amendment, because the whole point of
this registry is to stop implementation accidents becoming protocol.

| Tier | When | Rust's role |
|---|---|---|
| **Transcribe** | Rev 15 already fixes the logical fields | confirms nothing is missed |
| **Absorb as shipped** | compatibility is itself protocol-significant, as with the deployed `storage_set_id` of §5.2 | authoritative, because changing it breaks live commitments |
| **Design normatively** | the specification only names a concept | **evidence, not authority** |

Most of §6 falls in the third tier.
3. **A production encoder**, written from this text.
4. **An independent conformance encoder and parser**, written from this text by a path that
   does not call the production canonicalization helpers, so that a bug in one implementation
   cannot bless itself.
5. **Golden vectors**, generated by the production encoder, verified byte-for-byte by the
   independent one, and published as outputs of an already-defined schema rather than as its
   source of truth.

Anchor V2 remains blocked until `0x0001` is unblocked, because `h_n = c_{n-1}` is not
computable without `CCB(VaultStateV2)`.
