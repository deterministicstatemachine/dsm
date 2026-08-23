# CCB Object Registry — canonical cross-implementation commitment encoding

Establishes the CCB framework and the single object-class namespace for canonical
cross-implementation commitment encoding across DSM.

It began as, and remains, the normative companion to SoFi Revision 15
(`.github/instructions/sofispecs.instructions.md`) for finding 7 of
`docs/reports/2026-08-21-rev15-conformance-delta.md`. **Finding 7 remains OPEN.** It now also
carries **DSM substrate** object classes that are not Rev 15 objects — the Genesis v3 authority
parameters and the Device Tree root-progression objects of area 8, whose semantics were fixed by
[`docs/plans/2026-08-22-genesis-root-authority-and-device-tree-progression.md`](../plans/2026-08-22-genesis-root-authority-and-device-tree-progression.md).

They live here rather than in a second document for one reason: **there is one `u16` object-class
namespace, and two registries allocating from it independently would let two logical objects share
an encoding — Req 3.2's failure, arrived at by administrative accident rather than by encoding
ambiguity.** Substrate classes are marked as such in §3 and are excluded from §4's Rev 15 closure
accounting; they neither gate nor are gated by finding 7.

This document supplies the framework, the namespace and a complete gap inventory. It does not
make Rev 15's commitments independently derivable, because two of its twenty-one live
object classes still have no contents in the specification — see §4, §6 and the §6a audit.
Finding 7 closes when those are resolved by the normative amendments listed in §7, not when
this document merges.

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
`ta_B` and the Definition 6.17 settlement resource key are therefore not derivable from the
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

### 2.5 Sequences

```
sequence = u32_be(count) ‖ enc(e_1) ‖ enc(e_2) ‖ … ‖ enc(e_count)
```

Identical bytes to a set, and a **different type**. A sequence preserves the order it was
given: elements are **not** sorted, and duplicates are legal because position carries meaning.
A field table must say which it is, because the encoding cannot be told apart from the bytes.

Sequences exist because Rev 15 has ordered objects that a set cannot express. A route is "a
sequence of logical legs" with `r_i = ⟨A_{i,1}, …, A_{i,h}⟩`; reordering its hops is a
different route, not the same one written differently. Sorting there would silently merge
distinct routes into one encoding, which is the Req 3.2 failure the registry exists to
prevent — the same failure as collapsing a duplicate, arrived at from the opposite direction.

A **heterogeneous** sequence needs no union machinery. Every element is a complete CCB
beginning with its own `u16` class discriminant per §2.1, so a reader recovers each element's
type from the element itself. Rev 15's route legs are exactly this: "either a one-vault
allocation or a same-pair allocation bundle". Giving those two their own object classes makes
the leg union self-discriminating, where an ad-hoc tag inside `Route` would be a second,
redundant encoding of a fact the envelope already carries.

### 2.6 Maps

```
map = u32_be(count) ‖ (CCB(k_1) ‖ CCB(v_1)) ‖ … ‖ (CCB(k_count) ‖ CCB(v_count))
```

Pairs are sorted ascending by key CCB under the same comparison as §2.4. Duplicate keys are
invalid.

### 2.7 Nested objects

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

### 2.8 The discriminant and field-number namespace

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

**Retired schema versions are burned exactly like retired classes.** When a schema version is
replaced by a clean cut, its number is recorded as burned and never re-assigned, and **no production
path decodes, accepts, emits or falls back to it**. Recording it is not compatibility support — it
is what prevents a later version from silently reusing a number that once meant something else. A
registry that kept old schemas readable would be a coexistence plan, which beta does not have.

**Reserved ranges.** `0x0000` is reserved and never assigned, so an all-zero buffer is not a
valid CCB blob. `0xFF00`–`0xFFFF` are reserved for experimental and test object classes and
must never appear in a production commitment.

### 2.9 Signatures are not fields

A signature over an object is **never** a field of that object's CCB. The CCB *is* the signed
preimage; the signature travels beside it in transport and is verified against it.

The reason is ordering rather than taste: a signature is computed over the encoded object, so an
object that contained its own signature could not be encoded before it was signed, nor signed
before it was encoded. Any scheme that appears to do so is really encoding two different objects
and calling them one.

Where an object is both hashed and signed, the two are distinguished by domain tag over the same
bytes: one domain for its identity, another for its authorization. Using one domain for both would
make a digest and a signature preimage interchangeable, which is the confusion domain separation
exists to prevent.

**The domain-hash construction, stated once.** Everywhere this registry writes `H(<domain> ‖ x)`,
the bytes are exactly

```
H_dom(domain, x) = BLAKE3(domain_bytes ‖ 0x00 ‖ x)
```

where `domain_bytes` is the tag's ASCII spelling **without** a trailing NUL and containing no NUL
of its own, and `0x00` is the single separator. This is `dsm_domain_hasher`
(`dsm/src/crypto/blake3.rs:167-177`) and the `TaggedHashDomain` contract it enforces; the registry
absorbs it rather than inventing a second convention. A tag written here as `DSM/devtree-transition`
therefore contributes 22 bytes and one separator, never a NUL-terminated 23.

**The signing construction, stated once.** A signature over object `o` is

```
m_sig = H_dom(<signing-domain>, CCB(o))          # 32 bytes
σ     = SIGN(sk, m_sig)                          # per the object's declared signature_alg
```

The signed message is the 32-byte domain hash, **not** `<signing-domain> ‖ CCB(o)` passed to the
signer directly. Both readings satisfy the phrase "signed over a domain-separated digest of its
fields", and an implementation choosing either could claim conformance while producing signatures
the other rejects — precisely the implementation-defined byte this registry exists to eliminate. It
also matches what the tree already does: `RecoveryAuthorityAnchor` computes a 32-byte
domain-separated `anchor_digest` (`dsm/src/recovery/authority_anchor.rs:64-74`) and passes exactly
that to `sphincs_sign` / `sphincs_verify` (`:215-217`, `:139-147`), never a tagged concatenation.

Verification recomputes `m_sig` from the object's CCB and the declared domain. A verifier that
accepts a signature over any other preimage is non-conformant even if the signature is valid.

A signature carried in a protobuf message alongside CCB bytes is transport, per §2.10.

### 2.10 Relationship to transport

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
| `0x0001` | `VaultStateV2` (`V_n`) | **2** | `c_n = H(DSM/vault-state ‖ CCB)` | §5.1 defined; schema 1 **burned** |
| `0x0002` | `StorageSet` (`S`) | 1 | `storage_set_id = H(DSM/storage-set ‖ CCB)` | §5.2 defined |
| `0x0004` | `EncumbranceClaim` (`e_j`) | 1 | `e_j = H(DSM/enc-claim ‖ …)` | §5.3 defined |
| `0x0005` | `EncumbranceSet` (`{e_j}`) | 1 | `E = H(DSM/enc ‖ vault_id ‖ CCB)` | §5.3 defined |
| `0x0006` | `FulfillmentMechanism` (`M`) | 1 | `M = H(DSM/fulfillment ‖ vault_id ‖ c_0 ‖ CCB(B_M))`, signed as `CCB(M)` | **partial — §6** |
| `0x0007` | `MarketPolicy` (`P_M`) | 1 | nested in `0x0001` | §5.7 defined |
| `0x0008` | `MarketBounds` (`B_M`) | 1 | nested in `0x0006` | §5.6 defined |
| `0x0009` | `ReleasePolicy` (`P_R`) | 1 | nested in `0x0001` | §5.4 defined |
| `0x000A` | `FeePolicy` (`Φ`) | 1 | nested in `0x0001` | §5.9 defined |
| `0x000B` | `TradeIntent` | 1 | `I = H(DSM/intent ‖ CCB)` | §5.5 defined |
| `0x000C` | `RouteSet` (`R`) | 1 | nested in `0x0017` | §5.14 defined |
| `0x000D` | `Route` (`r_i`) | 1 | set element of `0x000C` | §5.13 defined |
| `0x000E` | `SettlementBundle` (`B`) | 1 | `b = H(DSM/settlement-bundle ‖ CCB)` | §5.6 partial |
| `0x000F` | `ConsumedDlvTransition` (`T_v`) | 1 | nested in `0x000E` | §5.6 partial |
| `0x0010` | `DlvProofMaterial` (`P_v`) | 1 | nested in `0x000E` | **blocked, see §6** |
| `0x0011` | `TraderAcceptance` (`TA_B`) | 1 | `ta_B = H(DSM/trader-settlement-acceptance/v2 ‖ CCB)` | §5.7 partial |
| `0x0012` | `TradeDigest` | 1 | `d = H(DSM/digest ‖ CCB)` | **blocked, see §6** |
| `0x0013` | `ReferenceWindow` (`{d_i}`) | 1 | `W = H(DSM/ref-window ‖ pair_id ‖ CCB)` | §5.8 defined |
| `0x0014` | ~~`ExternalCommitmentBody`~~ | — | — | **BURNED — §6a finding 3** |
| `0x0017` | `RouteCommitmentBody` (`Q`) | **2** | `X = H(DSM/route-set ‖ CCB(Q))` | §5.12 defined; schema 1 **burned** |
| `0x0015` | `Allocation` (`a`) | **2** | leg element; nested in `0x000D` | §5.10 defined; schema 1 **burned** |
| `0x0016` | `AllocationBundle` (`AB_{A→B}`) | 1 | leg element; nested in `0x000D` | §5.11 defined |
| `0x0018` | **substrate** `GenesisParamsV3` | 1 | `G = H(DSM/genesis/v3 ‖ CCB)` | §5.15 defined |
| `0x0019` | **substrate** `RootProgressionDelegation` (`D_i`) | 1 | `del_i = H(DSM/devtree-delegation ‖ CCB)`, and the GRK-signed bytes | §5.16 defined |
| `0x001A` | **substrate** `DeviceTreeRootTransition` (`T_j`) | 1 | `t_j = H(DSM/devtree-transition ‖ CCB)`, and the delegate-signed bytes | §5.17 defined |

`0x0000` reserved. `0x0014` is **burned**: it shipped on `main` as `ExternalCommitmentBody`,
and §6a finding 3 established there is no such object. Re-using that number for
`RouteCommitmentBody` would be exactly the semantic reassignment §2.8 forbids — an assigned
identity does not become vacant just because it never received a field table. `0x0003` is
**burned**: it was briefly assigned to a `StorageMemberId`
object class before §5.2 established that member ids are bare length-prefixed bytes inside a
frozen layout, with no envelope and therefore no class. Per §2.8 a retired class number is
never re-assigned. `0xFF00`–`0xFFFF` reserved for test classes.

**Burned schema versions.** `0x0001` schema 1, `0x0015` schema 1 and `0x0017` schema 1 are burned by
the state/route identity cut. They are recorded so their numbers are never re-assigned; no
production path decodes or emits them.

`0x0018`–`0x001A` are **DSM substrate**, not Rev 15 objects. They are allocated from this table
because the namespace is single and indivisible (§2.8), and they carry the same immutability rules
as every other assignment. They are excluded from §4's count and closure criteria.

### 3.1 Declared enumerations

Enumerations are `u16_be` per §2.2 over values declared here, never over values invented in a field
table. A field table names the enumeration; this section fixes its members.

**`signature_alg`** — identifies a signature algorithm together with the exact encoding of its
public keys and signatures.

| Value | Member | Public key | Signature |
|---|---|---|---|
| `0x0001` | `SPHINCS_PLUS_SPX256F` | 64 bytes (`2n`, `n = 32`) | 49,856 bytes |

Beta declares no other member. The value is committed wherever a public key is, so a future
variant can never be substituted for the committed one: the algorithm and the key bytes stand or
fall together.

**`authority_role`** — the scope a root-authority delegation confers.

| Value | Member | Meaning |
|---|---|---|
| `0x0001` | `DEVICE_TREE_ROOT_PROGRESSION` | may sign `0x001A` transitions for the named genesis, and nothing else |

Beta declares no other member. A role is deliberately narrow: the GRK exists to delegate one
capability, and a role that meant "may act for the owner" would make the delegation a universal
authority, which the area 8 semantics forbid.

## 4. Status of this registry

**This registry does not complete every field table, and says so rather than inventing the
missing ones.**

Of the **twenty-one live** object classes above — `0x0014` is burned and not counted:

- **15 are fully specified** in §5 — `0x0001`, `0x0002`, `0x0004`, `0x0005`, `0x0007`,
  `0x0008`, `0x0009`, `0x000A`, `0x000B`, `0x000C`, `0x000D`, `0x0013`, `0x0015`, `0x0016`,
  `0x0017`.
- **4 are partial** — `0x0006`, `0x000E`, `0x000F`, `0x0011` — where the specification fixes
  the field order or names the members but leaves types or a nested class open.
- **2 are blocked** — `0x0010` `DlvProofMaterial` and `0x0012` `TradeDigest`, both genuinely
  unspecified in Rev 15 and both belonging to amendment 2c.

The blocked ones are blocked because the specification names them without ever enumerating
their contents: `P_M` is "the bounded market-fulfillment policy" and nothing more. Writing a
field table for those would settle protocol in this document exactly as writing an encoder
first would settle it in Rust. §6 states precisely what each one needs.

The framework in §2 and the namespace in §3 are complete and are **not** blocked on §6. They
can be reviewed, merged, and implemented against for the ten specified objects immediately.

**Substrate classes are outside this count.** `0x0018`–`0x001A` are DSM substrate, fully specified
in §5.15–§5.17, and they do not enter the twenty-one live Rev 15 classes above. Finding 7 closes on
the Rev 15 amendments in §7 alone; nothing about the substrate classes advances or delays it. The
direction of independence runs both ways — the substrate objects are derivable now, whether or not
`0x0010` and `0x0012` ever are.

## 5. Field tables

*(Sections 5.1–5.8 follow the framework above. Objects marked blocked in §3 carry only their
class assignment until §6 is resolved.)*

### 5.1 `VaultStateV2` — class `0x0001`, schema 2

The fifteen members of the Def 4.1 tuple, numbered in the order that definition states them.
`c_n = H(DSM/vault-state ‖ CCB(V_n))`, and `h_n` — field 12 — is `c_{n-1}` for `n > 0` and the
domain-separated genesis value at `n = 0`.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `owner_genesis_id` (`g_o`) | `digest32` | |
| 2 | `owner_device_id` (`d_o`) | `digest32` | |
| 3 | `vault_id` | `digest32` | fixed at creation, never changes |
| 4 | `generation` (`n`) | `u64` | |
| 5 | `reserve_a` (`R_A`) | `u64` | base units of `P_M.token_a_policy_commit` |
| 6 | `reserve_b` (`R_B`) | `u64` | base units of `P_M.token_b_policy_commit` |
| 7 | `market_policy` (`P_M`) | nested `0x0007` | inline by value per §2.7 |
| 8 | `release_policy` (`P_R`) | nested `0x0009` | inline by value |
| 9 | `fee_policy` (`Φ`) | nested `0x000A` | inline by value; the single authoritative fee |
| 10 | `encumbrances` (`E`) | nested `0x0005` | the encumbrance set, inline by value |
| 11 | `iteration_budget` (`β`) | optional `u64` | §2.3 presence marker; absent is the common case |
| 12 | `parent_state_commitment` (`h_n`) | `digest32` | `c_{n-1}`, or the genesis value at `n = 0` |
| 13 | `owner_authority_transition_digest` (`r_o`) | `digest32` | `t_j = H_dom(DSM/devtree-transition, CCB(T_j))` — the `0x001A` transition under which the owner asserts the device authority signing for this vault |
| 14 | `storage_set` (`S`) | nested `0x0002` | inline by value; note `0x0002` carries the frozen legacy layout of §5.2 |
| 15 | `quorum` (`q`) | `u32` | the fixed threshold; validity is `q` conformant for `|S|` per the beta profile |

Reserve ordering follows the token pair in `P_M`: field 5 is the leg whose policy commitment is
`token_a_policy_commit`, which `0x0007` requires to be the lexicographically smaller of the two.
The pair is therefore not restated here — restating it would be the alias class the Def 5.2
amendment removed.

`q` is a field of the state rather than of `B_M`, and `S` likewise, because Def 4.1 makes both
members of `V_n`. `M` commits their birth values transitively through `c_0`.

**Field 13 — the committed device-authority position.** Rev 15 named `r_o` "the authenticated owner
root" once and defined it nowhere. Schema 2 gives it a definition and a name that matches its bytes:
a transition digest is not a "root". A trader authenticates `AK_pk` by discharging the area 8
predicate at this **bound position**, which is what closes the check without a freshness assumption.
The value is **invariant across market successors** — copied byte-for-byte, never advanced — because
a market successor executes while the owner is absent and must not move the owner-authority
reference. The position lives in the state rather than a separate object so a generation and its
authority position cannot disagree: they are one commitment. Semantics, publication and the
verification staging are in
[`docs/plans/2026-08-23-sofi-authority-position-commitment.md`](../plans/2026-08-23-sofi-authority-position-commitment.md).

**Schema 1 is burned.** It carried the undefined `owner_root` and is not decodable by any production
path. Its number is recorded only so it is never re-assigned.

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

### 5.4 `ReleasePolicy` — class `0x0009`, schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `family_id` | `u16` | `0x0001` = `OWNER_LOCAL_FULL_CLOSE`. Beta declares no other member |
| 2 | `family_version` | `u16` | `1` for beta; fixes the admissible successor shape and the evaluation budget |

**No parameters, deliberately.** The beta family admits exactly one successor shape — both
reserve legs drained to zero in one transition, each leg's exact remaining amount credited to
ordinary owner balance, the vault retired. The amounts are the parent's reserves, the
destination is ordinary owner balance, the authority is the owner signature over the exact
successor, and the timing is Req 6.30's. A parameter here would be a value some verifier could
read differently from the parent state, which is what Req 4.6's decidability condition forbids.

A partial-release family would need a released amount per leg — precisely the parameter this
family does not have — and so takes a new `family_id` under a new schema version rather than an
optional field bolted onto this one.

`evaluation_budget` is a constant of `family_version`, as in `0x0007`.

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
specification excludes them, and §2.8 forbids extending a shipped schema version.

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

### 5.10 `Allocation` — class `0x0015`, schema 2

Def 9.1: `a = (vault_id, parent_binding, Δ_in, Δ_out, e, Φ)`.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `vault_id` | `digest32` | |
| 2 | `parent_binding` | `digest32` | `c_n = H_dom(DSM/vault-state, CCB(V_n))` — the exact complete current state |
| 3 | `delta_in` | `u64` | base units into the DLV |
| 4 | `delta_out` | `u64` | base units out of the DLV |
| 5 | `encumbrance_claim` (`e`) | `digest32` | the single claim this allocation consumes, `e_j` of §8 — **not** `EC_v` |
| 6 | `fee_policy` (`Φ`) | nested `0x000A` | inline by value |

No token pair: `c_n` commits `P_M`, which commits the pair.

**Schema 2 replaces `p_v` with `c_n`, and schema 1 is burned.** The reason is not that `p_v`
duplicated anything — normatively it is a single digest. It is that `p_v` commits only a *selected
projection* of `V_n` (vault id, generation, the predecessor edge `h_n`, the reserves digest, `S`,
`q`), whereas `c_n` commits the **exact complete current state**. A parent identity that omits parts
of the parent is a parent identity that cannot detect changes in the parts it omits.

### 5.11 `AllocationBundle` — class `0x0016`, schema 1

Def 9.2: `AB_{A→B} = {a_1,…,a_f}`, `1 ≤ f ≤ max_fanout`, every member converting the same
input token to the same output token and naming a **distinct** DLV.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `allocations` | set of `0x0015` | §2.4 ordering; "canonicalized by vault identifier" is satisfied because `vault_id` is field 1 of the element, so ordering by element CCB orders by vault id |

`max_fanout` is **not** a field — it is authoritative in `TradeIntent` field 7, and the member
count is checked against it. Distinct-DLV is a validity condition on construction: two members
sharing a `vault_id` are refused, not merged.

The ordering claim is worth stating precisely rather than assuming. Element CCB begins
`u16 class ‖ u16 schema ‖ vault_id`, and class and schema are equal across members of one
bundle, so lexicographic order over element CCB **is** order by `vault_id` — with ties
impossible, since a duplicate `vault_id` is refused.

### 5.12 `RouteCommitmentBody` — class `0x0017`, schema 2

`X = H(DSM/route-set ‖ CCB(Q))`. Replaces the four-operand concatenation of §9.3.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `intent` (`I`) | `digest32` | `H(DSM/intent ‖ CCB(TradeIntent))` |
| 2 | `route_set` (`R`) | nested `0x000C` | inline by value |
| 3 | `nonce_x` | `digest32` | |

**Schema 2 removes `{EC_v}`, and schema 1 is burned.** Schema 1 carried it for a reason the registry
stated explicitly: `{EC_v}` "is not implied by `p_v`, which commits the parent state commitment
`h_n` and the current generation's reserves digest, but **not** the current generation's encumbrance
set." That justification was conditional on `p_v`, and it does not survive `c_n`. `E` is a field of
`V_n`, so `c_n` commits the current generation's encumbrance set already — through every allocation
in `R`, each of which now binds `c_n` for its own vault.

Keeping `{EC_v}` beside `c_n` would commit the same encumbrance state twice in one object, in two
independently encodable values free to disagree. That is the alias class this registry has removed
from `B_M`, from the transition object and from the `Allocation` parent binding, and it would be
reintroduced here by inertia rather than by argument.

**`Allocation` field 5 stays.** `e` is not an alias of anything `c_n` commits: `c_n` *authenticates
the parent's entire encumbrance state*, while `e` *selects the one claim this allocation consumes*.
Authentication and selection are different jobs, and no amount of parent commitment tells a verifier
which claim a leg is spending.

### 5.13 `Route` — class `0x000D`, schema 1

§9.3: "A route is a sequence of logical legs, each leg being either a one-vault allocation or
a same-pair allocation bundle", `r_i = ⟨A_{i,1},…,A_{i,h}⟩`, `h ≤ max_hops`.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `legs` | **sequence** of `0x0015` \| `0x0016` | §2.5 ordering — emitted in route order, **never sorted** |

One field, deliberately. `max_hops` is not carried: it is authoritative in `TradeIntent`
field 6, and route validity checks `len(legs) ≤ max_hops` against the intent the route serves.

**Sequence, not set** — this is the distinction §2.5 exists for. A route's hops are ordered by
execution; reordering them is a *different route*, not the same one written differently.
Sorting here would map two distinct routes onto one encoding, which is Req 3.2's failure
reached from the opposite direction to collapsing a duplicate.

**The heterogeneous element needs no tag.** Each leg is a complete CCB opening with its own
`u16` class, so a reader sees `0x0015` or `0x0016` and knows what follows. A discriminant
field inside `Route` would re-encode what the envelope already carries, and the two could then
disagree.

A leg count of zero is invalid: a route with no legs executes nothing and would give the empty
sequence a meaning the specification does not define.

### 5.14 `RouteSet` — class `0x000C`, schema 1

§9.3: `R = {r_1,…,r_k}`, "canonicalized by route CCB ascending", with `k` bounded by
`TradeIntent.k`.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `routes` | set of `0x000D` | §2.4 ordering over complete `Route` CCB; duplicates invalid |

`k` is not carried, for the same reason `max_hops` is not: Req 9.1 makes it a `TradeIntent`
bound — and explicitly an *independent* one, warning that "an implementation must not use `k`
as the fanout limit". The set's cardinality is checked against `TradeIntent` field 8.

Two routes with identical legs in identical order are the same route, so a duplicate is a
producer bug and is refused rather than collapsed. Note this is genuinely a **set** while its
elements are **sequences** — the alternatives `R` retains are unordered, the hops inside each
are not.

---

*Sections 5.15–5.17 are **DSM substrate**, not Rev 15 objects. Their semantics are fixed by
[the area 8 root-authority design](../plans/2026-08-22-genesis-root-authority-and-device-tree-progression.md);
this registry supplies only their bytes.*

### 5.15 `GenesisParamsV3` — class `0x0018`, schema 1

`G = H(DSM/genesis/v3 ‖ CCB(GenesisParamsV3))`. The genesis identifier is a commitment to its own
parameters, and the Genesis Root Key is one of them — which is what lets a verifier holding `g_o`
authenticate `GRK_pk` by recomputation, with no fetch and no signature.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `genesis_nonce` | `digest32` | public; `KDF(wallet_seed, DSM/genesis-public-nonce/v2 ‖ network_id ‖ wallet_index)` |
| 2 | `network_id` | `bytes` | length-prefixed; the v2 preimage concatenated it bare |
| 3 | `genesis_version` | `u32` | `3` for this class; big-endian, where the v2 preimage was little-endian |
| 4 | `grk_alg_id` | enum `signature_alg` | fixes the key encoding of field 5 |
| 5 | `grk_pk` | `bytes` | the exact Genesis Root Key public key, not a commitment to it |

Field 5 is the key itself. A `digest32` commitment to it would need its own preimage rules — the
same canonicalization question one layer down, which §2.7 refuses for nested objects and which is
refused here for the same reason. `G` is already a hash; folding the key directly *is* the
commitment.

`network_id` is length-prefixed and `genesis_version` is big-endian, both departures from the
shipping v2 preimage (`genesis_v2.rs:92-103`), which concatenates `network_id` bare and emits the
version little-endian. The length prefix is forced: this preimage now holds **two** variable-length
fields, `network_id` and `grk_pk`, and unprefixed concatenation does not determine where the first
ends and the second begins. One bare variable-length field can survive by being recoverable from
the remaining fixed widths; two cannot. Big-endian is §2.2's rule and needs no separate
justification beyond consistency.

No compatibility claim is made or needed. This class is a clean cut against a new
`genesis_version`, and a v2 identity cannot be re-encoded into it in any case, because its `G`
committed a preimage that contained no key at all.

**Not in this object.** `device_slot`, `authority_policy_hash`, `AttA` and any device key.
`GenesisParamsV3` fixes the identity and its root authority; every device-scoped value derives from
`G` and therefore cannot appear inside it without circularity.

### 5.16 `RootProgressionDelegation` — class `0x0019`, schema 1

`del_i = H_dom(DSM/devtree-delegation, CCB(D_i))` is the identity. The GRK signature is over
`H_dom(DSM/devtree-delegation-sign, CCB(D_i))` — two domains, one preimage, both constructions
fixed in §2.9. The signature is not a field.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `genesis_id` (`g_o`) | `digest32` | binds the delegation to one identity; not replayable under another |
| 2 | `role` | enum `authority_role` | `0x0001` in beta |
| 3 | `role_version` | `u16` | a changed role semantic requires a new value, never silent acceptance |
| 4 | `delegated_alg_id` | enum `signature_alg` | fixes the key encoding of field 5 |
| 5 | `delegated_pk` | `bytes` | the authorized key, **named by key**, never by DevID or tree position |
| 6 | `delegation_number` | `u64` | monotone from 0 |
| 7 | `parent_delegation_digest` | `digest32` | `del_{i−1}`; the §5.18 delegation sentinel at `i = 0` |
| 8 | `activation_transition_digest` | `digest32` | the transition **after** which this delegation takes effect; the §5.18 transition sentinel at `i = 0` |

Field 5 carries a key and not an identifier because the delegation's validity must not depend on
the Device Tree it authorizes changes to. Naming a DevID here would route the delegation's
authority through the tree, which is the circularity the whole construction avoids.

Field 8 names a **transition digest, not a root value**, because root values recur: the shipping
suite asserts that the root at `version_number = 2` equals the version-0 root after an add and a
remove (`dsm_sdk/src/sdk/storage_node_sdk.rs:4695-4713`). A root value is not a unique chain
position and would activate a delegation at two places at once.

### 5.17 `DeviceTreeRootTransition` — class `0x001A`, schema 1

`t_j = H_dom(DSM/devtree-transition, CCB(T_j))` is the identity; the delegated key signs
`H_dom(DSM/devtree-transition-sign, CCB(T_j))`, per §2.9.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `genesis_id` (`g_o`) | `digest32` | without it a transition is replayable across identities |
| 2 | `predecessor_transition_digest` | `digest32` | `t_{j−1}`; the §5.18 transition sentinel at `j = 0` |
| 3 | `new_root` (`R_G,j`) | `digest32` | the Device Tree Merkle root this transition establishes |
| 4 | `version_number` | `u64` | strictly monotone; an ordering assertion, not the ancestry mechanism |
| 5 | `delegation_digest` | `digest32` | `del_i` of the delegation this transition acts under |

Fields 1, 2 and 5 are all absent from today's `DeviceTreeRootUpdateV1`
(`proto/dsm_app.proto:3732-3737`), whose only content fields are `old_root`, `new_root` and
`version_number` beside a signature. That message is replaceable rather than adoptable.

**Field 2 is an edge, not a state value, and there is no `old_root`.** Root values recur — §5.16
cites the shipping assertion — so `old_root` plus a monotone version does **not** identify a unique
predecessor. One signed transition would attach at two positions with two different ancestries, and
a party withholding two transitions could shorten an ancestry until a superseded delegation's
activation fell out of scope and a retired key's signature verified. The amendment recorded under
*Transition* in the area 8 semantics carries the counterexample in full.

`old_root` is not retained alongside field 2. The predecessor's `new_root` supplies the state value,
so keeping it would restate a derivable fact and create a disagreement surface — a transition naming
predecessor `P` while asserting an `old_root` that is not `P.new_root`. An implementation may carry
that continuity assertion in transport; it is not part of the committed object.

An earlier revision of this section argued the opposite, treating `old_root` and the predecessor
digest as two encodings of one fact under the Def 5.2 anti-aliasing doctrine. That was wrong, and
root recurrence is the proof: a state value that can appear at many positions and a history edge
that appears at exactly one are different facts, not two spellings of one.

### 5.18 Genesis sentinels

Two chain-origin values, fixed here because the area 8 semantics deliberately deferred their bytes
to the encoding layer.

| Sentinel | Value | Used by |
|---|---|---|
| delegation origin | `H(DSM/devtree-delegation/genesis-sentinel/v1)` | `0x0019` field 7 at `i = 0` |
| transition origin | `H(DSM/devtree-transition/genesis-sentinel/v1)` | `0x0019` field 8 at `i = 0`; `0x001A` field 2 at `j = 0` |

Each is `H_dom(tag, ε)` — the §2.9 construction over **empty input**, i.e. `BLAKE3(tag ‖ 0x00)`.
A constant, not a function of the genesis. Three properties fix the shape, and a fourth fixes its scope.

**Domain-separated rather than all-zero.** An all-zero digest is a value a buggy producer reaches
by accident, so it cannot distinguish "origin of chain" from "field never populated". These cannot
be produced accidentally and cannot collide with a real digest, whose domain tag differs.

**Two sentinels, not one.** A delegation origin and a transition origin are different kinds of
position. Sharing one value would let a delegation-parent field validate against a transition
origin, which no rule would then catch.

**Constant, not per-genesis.** Every object that carries a sentinel already binds `genesis_id` in
field 1, so parameterizing the sentinel by genesis would restate a fact the object already commits —
the same aliasing §5.17 declines above. This is the one respect in which these differ from Rev 15's
`h_0 = H(DSM/vault-state-parent/genesis/v2 ‖ vault_id)`, which is parameterized because `c_0` must
differ per vault and `V_n` has no other field forcing it to.

**One sentinel serves both the delegation activation at `i = 0` and the transition predecessor at
`j = 0`,** because both denote the same thing: the position before `T_0`. `act(D_0)` means
"effective from the start of the chain", which is exactly `T_0`'s predecessor.

## 6. Blocked objects — what each one needs

These object classes are assigned but cannot be given field tables from Revision 15 as
written. Each entry states the exact missing decision. **None of them should be resolved by
writing an encoder.**

| Class | Object | What the specification says | What is missing |
|---|---|---|---|
| `0x0010` | `DlvProofMaterial` `P_v` | "proof material required to verify and later compose that DLV continuation" | the entire contents; likely a witness family rather than a flat record |
| `0x0012` | `TradeDigest` | commits "the pair, executed amounts, participating vault identifiers, parent bindings, fees, and `X`" | six named components with no types and no ordering for the multi-valued ones |

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

## 6a. Amendment 2b — opening object audit

Run before any `Route` field number is frozen, because §2.8 makes them permanent. Four
findings; two are settled by the audit and two need a decision.

### The object graph Rev 15 already fixes

`p_v` is **not** an open question. Def 9.1 defines an allocation as
`a = (vault_id, parent_binding, Δ_in, Δ_out, e, Φ)`, and Def 6.4 defines that
`parent_binding` as the history-bound `p_v`. A route is a sequence of legs over those
allocations. The legacy `RouteCommitHopV1.vault_state_anchor_digest` therefore has no
normative future, and it is evidence of past behaviour rather than a template — nothing gets
canonized merely because that is where the old implementation put it.

```
Allocation        a   = (vault_id, p_v, Δ_in, Δ_out, e, Φ)          0x0015
AllocationBundle  A_B = {a…}, one token pair, by vault id           0x0016
Route             r_i = ⟨leg…⟩, leg ∈ {Allocation, AllocationBundle} 0x000D
RouteSet          R   = {r…}, ordered by complete Route CCB          0x000C
```

### Finding 1 — `Allocation` and `AllocationBundle` were missing (settled)

Rev 15 defines both and even reserves the `DSM/allocation` domain, but neither had a class.
`Route` contains them, so `CCB(Route)` was unspecifiable from the bottom up. Assigned `0x0015`
and `0x0016`.

### Finding 2 — a route is an ordered sequence, and the framework had no sequence type (settled)

§2.4 defines sets, §2.6 maps, and nothing ordered. §9.3 says a route is "a sequence of logical
legs"; sorting one would merge distinct routes into a single encoding. §2.5 now defines a
sequence: identical bytes to a set, a different type, order preserved and duplicates legal.

The heterogeneous leg needs **no union machinery**. Every element is a complete CCB starting
with its own class discriminant, so a leg is self-discriminating. An ad-hoc tag inside `Route`
would be a second encoding of a fact the envelope already carries.

### Finding 3 — `X` was overloaded; resolved to the body model (settled)

Two incompatible uses:

- §7.2: `ExtCommit(X) = H(DSM/ext ‖ Canon(X))` — `X` as a **body** with a canonical encoding.
- §9.3: `X = H(DSM/route-set ‖ I ‖ Canon(R) ‖ Canon({E_v}) ‖ nonce_X)` — `X` as a **digest**.

A digest has no `Canon`, so both could not be right. Resolved as:

```
Q = RouteCommitmentBody(…)
X = H(DSM/route-set ‖ CCB(Q))
ExtCommit(X) = H(DSM/ext ‖ X)
```

`X` is always a 32-byte route-commitment digest. `Canon(X)` disappears, because a digest is
already a primitive. The body becomes the canonical object.

**This deliberately changes §9.3's preimage**, from a four-operand concatenation to one body
encoding. That is the correct direction: the concatenation is precisely the pre-registry
construction being replaced, and preserving it only to avoid a preimage change would make the
registry ceremonial rather than authoritative.

**`0x0014` is burned rather than reused.** It shipped on `main` as `ExternalCommitmentBody`,
and §2.8 forbids reassigning a shipped identity to different semantics. An assigned class does
not become vacant because it never received a field table. `RouteCommitmentBody` takes a fresh
`0x0017`.

### Finding 4 — `A_B` denoted two objects; both renamed (settled)

Def 6.26's trader-acceptance artifact and Def 9.2's allocation bundle shared one symbol with
different subscript meanings. Renamed mechanically, so no later cross-reference depends on
prose context:

| Object | Symbol | Class |
|---|---|---|
| Trader acceptance for SettlementBundle `B` | `TA_B` | `0x0011` |
| Allocation bundle for token pair `A→B` | `AB_{A→B}` | `0x0016` |

Bare `A_B` is retained for neither, and the derived digest follows the artifact: Def 14.1's
`a_B` becomes `ta_B`, so the symbol and its digest cannot drift apart. This matters most for
amendment 2c, where
`TraderAcceptance` is security-critical and a reader resolving the wrong definition would be
reading about routing.

### Finding 5 — `{E_v}` and `e` are different facts (settled from source)

Resolved by evidence rather than by decision, and one premise for the question turned out not
to hold.

**Collision across vaults cannot occur.** `EC_v = H(DSM/enc ‖ vault_id ‖ Canon(E))` puts the
vault identifier inside the preimage, so two distinct vaults cannot produce equal commitments
absent a hash collision. A keyed map is unnecessary; a set suffices, and the verifier
recomputes `EC_v` for each vault named in `R` and tests membership.

**`e` is a claim, not a commitment.** Req 8.2 reads `∑_{e ∈ E_t} amount(e) ≤ R_t` — it
iterates `E` and calls `amount(e)` on each element, so lowercase `e` ranges over individual
claims. Def 9.1's lowercase singular `e` is that: the claim one allocation consumes.

**`{EC_v}` is not implied by `p_v` either.** `p_v` commits `vault_id`, `generation`, the
**parent** state commitment `h_n`, the reserves digest, the storage set and `q`. The current
generation's encumbrance set lives in `V_n` and is not among them. So `{EC_v}` binds a fact no
other operand of `X` binds.

Both therefore belong, and they are not the `P_M`/`Φ` alias pattern.

> **Superseded in part by the state/route identity cut.** The `e` half stands unchanged: it is a
> claim, not a commitment, and no parent identity can say which claim a leg spends. The `{EC_v}`
> half does not survive, and its own reasoning is why — it held only "because `p_v` … commits the
> parent state commitment `h_n`". Schema-2 `Allocation` binds `c_n`, which commits `E` directly, so
> `{EC_v}` no longer binds a fact no other operand binds; it restates one. `0x0017` schema 2 drops
> it (§5.12). Recorded rather than rewritten: the finding was correct against the premise it had.

### Finding 7 — `E` was overloaded too (settled)

The same defect as `X` and `A_B`, a third time. Def 4.1 lists "`E` the encumbrance set" as a
member of `V_n`, Req 8.2 iterates `E` as a set — and §8 also wrote
`E = H(DSM/enc ‖ vault_id ‖ Canon({e_j}))`, making `E` a digest in the same section that sums
over it.

The set keeps the name `E`, because that is what `V_n` contains and what Req 8.2 iterates. The
digest becomes `EC_v`. Only the set is a member of `V_n`; `EC_v` is derived from it.

Three symbol overloads in one specification is a pattern rather than three slips. Each was a
container and its commitment sharing a name — `X` body/digest, `A_B` acceptance/bundle, `E`
set/digest — and each was invisible until a field table forced the question of what the symbol
denotes. Later amendments should expect more of them wherever a `Canon(...)` or an `H(...)`
sits next to a set.

### Finding 6 — ownership of the bounds (settled)

Applying the anti-alias rule to three questions this audit exposed:

| Object | Holds | Does **not** hold | Because |
|---|---|---|---|
| `Route` `0x000D` | the ordered leg sequence | `max_hops` | authoritative in `TradeIntent` `0x000B` field 6; `Route` validity checks `len(legs) ≤ max_hops` |
| `AllocationBundle` `0x0016` | the canonical allocations | `max_fanout` | authoritative in `TradeIntent` field 7; the member count is checked against it |
| `AllocationBundle` `0x0016` | — | the token pair, by default | `p_v` binds the DLV parent, whose state already commits its canonical pair through `P_M`. Carrying it again creates a two-source equality invariant |

The token-pair exclusion is a default, not a certainty: if independent verification turns out
to need the pair as a distinct fact rather than a derived one — a verifier that has the bundle
but not the parent states — then it belongs, and the reason should be written down. Absent
that, it is derived.

### What remains blocked

`TradeDigest` `0x0012` stays last by dependency: §10 binds "the pair, executed amounts,
participating vault identifiers, parent bindings, fees, and `X`", and those types are
determinate only once findings 1–3 are settled.

---

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
   take new object or schema versions later, which is exactly what §2.8 provides for.

   The existing Rust `FulfillmentMechanism` enum spans Payment, CryptoCondition,
   MultiSignature, StateReference, RandomWalk, Bitcoin HTLC, AND/OR and AMM constant product.
   That is a legacy DLV mechanism family, and its breadth is **not** evidence that those
   variants belong inside a Rev 15 `P_M`. Preserve the intentional AMM facts — canonical
   token-policy identities, constant-product semantics, fixed fee representation, and actual
   reserves living outside the predicate — and design the normative objects from Rev 15's beta
   semantics rather than canonizing the enum.

   **2b. Routing and commitment profile — COMPLETE.** `Route` `0x000D`, `RouteSet` `0x000C`,
   `Allocation` `0x0015`, `AllocationBundle` `0x0016` and `RouteCommitmentBody` `0x0017` are
   specified; `ExternalCommitmentBody` `0x0014` is burned. The original framing follows, kept
   for the record:

   **2b (as originally scoped).** `Route` `0x000D`, `RouteSet` `0x000C`,
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

   **Prerequisite inside 2c.** `TA_B` carries ordinary DSM successor material
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

### The substrate classes are not in this queue

`0x0018`–`0x001A` are fully specified in §5.15–§5.17 and are not waiting on any amendment above.
They are ready for steps 3 and 4 immediately, and are gated instead by their own dependencies,
which live outside this registry: **area 4's immutable publication** — without it, transitions
still land in a mutable version-ordered slot that one anonymous write can hold indefinitely — and
the **owner-authenticated SoFi authority-position commitment**, which no shipping object carries
today.

They also answer, by precedent, the *Core canonical-successor encoding prerequisite* raised inside
2c above. That prerequisite asked where non-SoFi canonical bytes should be specified when SoFi
depends on them. The answer these three classes establish is: **here, in this namespace, marked
substrate and excluded from Rev 15's closure accounting** — never restated ad hoc inside a SoFi
amendment, and never in a second registry with its own numbering. The successor encoding itself
remains unwritten; only its home is settled.

3. **A production encoder**, written from this text.
4. **An independent conformance encoder and parser**, written from this text by a path that
   does not call the production canonicalization helpers, so that a bug in one implementation
   cannot bless itself.
5. **Golden vectors**, generated by the production encoder, verified byte-for-byte by the
   independent one, and published as outputs of an already-defined schema rather than as its
   source of truth.

**Anchor V2 is unblocked.** `0x0001` is specified in §5.1, so `c_n = H(DSM/vault-state ‖
CCB(V_n))` is computable and therefore so is `h_n = c_{n-1}`. What remains before Anchor V2 can
be *implemented* is step 3 of this list, not another normative amendment: an encoder that emits
`CCB(VaultStateV2)` and is checked against an independent one.

The five still-blocked classes — `0x000C`, `0x000D`, `0x0010`, `0x0012`, `0x0014` — belong to
the routing and settlement amendments and do not gate Anchor V2.
