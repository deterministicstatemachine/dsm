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
make Rev 15's commitments independently derivable, because two of its twenty-two live
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
and it ends the moment a second implementation exists. §5.2 **replaces** that layout with an
ordinary CCB object. An earlier revision absorbed it as shipped, on the ground that deployed signed
anchors already committed it — the state-identity cut deletes those anchors and reprovisions, so the
only reason to keep it is gone.

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

**Byte counts in this document are DERIVED, and nesting propagates them.** §2.7 already makes a
nested schema bump propagate upward mechanically; the same is true of a nested object's *size*, and
that consequence is easier to miss because no envelope changes to announce it. A `§5` section
stating "N bytes" is a computed value, not a constant: when a nested class gains, loses or resizes a
field, every enclosing section's count must be recomputed in the same change.

This is recorded because it was violated once. Amendment 2c-D ruling D3 gave `0x0032` a second
field, taking it from 36 to 68 bytes. §5.41's own count was corrected; §5.40's, which nests it, was
not — leaving `TraderAcceptance` pinned at 8,276 when its canonical encoding is 8,308. Nothing
caught it until an encoder was written against the section and disagreed by exactly 32 bytes. A byte
count no implementation has yet reproduced is an assertion, not a fact.

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

**Every reserved value appears in this registry (amendment 2c-C1 ruling D).** RESERVED is an
allocation state in its own right — it is not "unallocated", not a class, and not burned. Every
`u16` protected by the implementation's reserved-value guard MUST appear in §3 as reserved,
carrying any named reservation purpose. Reserved entries receive no §5 field table and have no
schema. Promoting a reserved value into a class is a normative change to this registry and must
ship with the corresponding code change and collision test. A number defended only in code is a
number this registry cannot keep from being reallocated by accident.

The reserved set is exactly `0x002A`–`0x002F`, six values, and §3 carries all six. `0x0032` was
**not** reserved — it was unallocated, held in prose for amendment 2c-D. That amendment has since
allocated it as the bundle-acceptance leaf state, and §3 carries its row.

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

#### Named exception 1 — `BindingRecordWireV1`

Amendment 2c-C2 ruling F freezes this structure outside CCB, and names it so that it can never be
cited as a general precedent. (Amendment 2c-F R1 names a second, `RC*`, below, on its own ground.)

```text
BindingRecordWireV1 is a frozen storage-layer canonical BYTE GRAMMAR.
It is NOT a CCB object: no CCB class, no schema envelope, no field table here.

Class N hashes the exact BindingRecordWireV1 bytes it stores.
Class N MUST NOT decode CCB or application objects to compute these identities.

record_digest_of_bytes, record_set_keys and record_set_digest are defined over
the exact frozen BindingRecordWireV1 bytes.
```

The exception exists because the storage node's design *is* "hash what I physically store without
interpreting it". Cutting protobuf here the way the economic identities were cut would push CCB
parsing **into Class N**, across the boundary that keeps a storage node from interpreting
application objects. The economic cases were different in kind: they leaked a transport
serialization into *application-semantic* identity.

The shipping `to_proto().encode_to_vec()` output is byte-identical to the grammar and is its
**present implementation** — evidence, never the definition. Leaving `prost::encode_to_vec()` as the
normative authority would make a library the protocol, which is the failure this section exists to
prevent. Future changes to those bytes require an explicit storage-wire version or amendment; **a
protobuf library refactor MUST NOT silently change them.**

This is a narrowly named storage-substrate exception. **It is not permission for arbitrary
protobuf-derived identities**, and no other object may cite it.

#### Named exception 2 — `RC*`, the RouteCommitV1 commitment form (amendment 2c-F R1)

```text
RC*  =  the proto3 binary encoding of RouteCommitV1 (proto/dsm_app.proto, version 2)
        with initiator_signature empty: fields in ascending field number,
        implicit-presence scalars equal to their default omitted, hops in carried
        order with each RouteCommitHopV1 encoded likewise, no unknown fields
X    =  H_dom(DSM/ext, RC*)
```

`RC*` is computed over the re-encoding of the decoded message. It is the preimage of `X` and of the
initiator's SPHINCS+ signature, and it is **never** a CCB blob. The signed `RC` rides inside `B` as
field 9 of the `DlvSettleOperationPreimageV1` in `MarketTerms.recovery_material.operation_bytes`
(§5.23), so `X` is recomputable from `B` alone.

2c-F R1 ratified it rather than cutting it to a CCB `Q` because it shipped: the settler's operation
signature, `b`, the `0x0021` leaves and every owner apply already commit to this `X`. That is its
own ground, not a citation of exception 1. It permits no other protobuf-derived identity. The
grammar is pinned by bytes, not by `prost`, in `dsm/tests/route_commitment_x_conformance.rs`: the
expected bytes there are written by hand, so a protobuf-library refactor that moved them is caught.

### 2.11 Authenticated retrieval — the retrieval obligation

Fetching an addressed object is not the same as obtaining it. The retrieval obligation is stated at
framework level because it governs every addressed object in this registry, not only the economic
ones.

> **Every fetch of an addressed object is followed by recomputing that object's canonical identity
> over the bytes actually returned, and comparing it to the address that was asked for, BEFORE any
> field of the object is read.** A mismatch is a refusal, never a repair.

A successful decode is **not** a substitute. Decoding proves the bytes are well-formed; it says
nothing about whether they are the bytes that address names. Canonicality and authenticity are
different properties, and only the second is at issue here. Strict decode-plus-re-encode equality
makes an address *exact given a byte string* — it cannot tell you the byte string is the right one.

The obligation is the **consumer's**, deliberately, and never the fetcher's: a fetcher is an
untrusted I/O boundary, and "the fetcher must return honest bytes" is not a rule a verifier can
check.

The recomputed value is the **inner** identity `H_dom(N, P)` per 2c-C1 ruling A. The outer
storage-object address is what was used to reach the storage layer; it is never what the comparison
is against, because it is not the object's identity.

**Rev 15 §15.3 is reconciled to this, not the reverse.** Rev 15 writes

```text
addr(P) = H(DSM/storage-object ‖ N ‖ H(N ‖ P))
```

which names no hash function, has no `0x00` separator, and imposes no length discipline on the
variable-length namespace `N`. **Taken literally it is not injective in `N`**: `N = "ab"` with
`P = "c"` and `N = "a"` with `P = "bc"` are the same byte string, so two distinct namespaces can
collide by concatenation alone. The frozen construction is §2.9's:

```text
inner  =  H_dom(N, P)  =  BLAKE3(N ‖ 0x00 ‖ P)
```

The `0x00` separator restores injectivity in `(N, P)` — **but only because §2.9 additionally
requires `N` to contain no NUL of its own.** The separator alone would not be enough: without that
condition, `N = "a\x00b", P = "c"` and `N = "a", P = "b\x00c"` produce the same preimage, and the
concatenation ambiguity returns one byte deeper. Injectivity here is a property of the pair
(NUL-free tag, separator), never of the separator by itself.

The shipped construction is the more specific and is the one frozen here; **the specification text
is corrected to match it**, rather than the code changed to match a form that is ambiguous as
written.

Because a rule discharged by open-coding at eleven sites is a rule that will be missed at the
twelfth, the obligation must be discharged by **a single named construct** through which a consumer
cannot obtain a usable object without the comparison having happened — the idiom
`ValidatedEconomicRoot` already uses, with a private field and no public conversion from its
unvalidated counterpart.

## 3. Object-class registry

The single namespace. Every canonical object in Revision 15 that feeds a hash, a signature, a
storage address, a resource key or an authority check appears here.

| Class | Object | Schema | Commitment it feeds | Status |
|---|---|---|---|---|
| `0x0001` | `VaultStateV2` (`V_n`) | **4** | `c_n = H(DSM/vault-state ‖ CCB)` | §5.1 defined; schemas 1, 2 and 3 **burned** |
| `0x0002` | `StorageSet` (`S`) | **3** | `storage_set_id = H(DSM/storage-set ‖ CCB)` | §5.2 defined; schemas 1 and 2 **burned** |
| `0x0004` | `EncumbranceClaim` (`e_j`) | **2** | `e_j = H(DSM/enc-claim ‖ …)` | §5.3 defined; schema 1 **burned** |
| `0x0005` | `EncumbranceSet` (`{e_j}`) | **2** | nested in `0x0001`; `EC_v` **deleted** | §5.3 defined; schema 1 **burned** |
| `0x0006` | `FulfillmentMechanism` (`M`) | 1 | `M = H(DSM/fulfillment ‖ c_0 ‖ CCB(B_M))`, signed as `CCB(M)` | **partial — §6** |
| `0x0007` | `MarketPolicy` (`P_M`) | 1 | nested in `0x0001` | §5.7 defined |
| `0x0008` | `MarketBounds` (`B_M`) | 1 | nested in `0x0006` | §5.6 defined |
| `0x0009` | `ReleasePolicy` (`P_R`) | 1 | nested in `0x0001` | §5.4 defined |
| `0x000A` | `FeePolicy` (`Φ`) | 1 | nested in `0x0001` | §5.9 defined |
| `0x000B` | `TradeIntent` | **2** | `I = H(DSM/intent ‖ CCB)` | §5.5 defined; schema 1 burned by 2c-E |
| `0x000C` | ~~`RouteSet`~~ | — | — | **BURNED by 2c-F R1** — schema 1 burned by the route cut; schema 2 never encoded |
| `0x000D` | `Route` (`r_i`) | **2** | nested in `0x0033` field 3 | §5.13 defined; schema 1 **burned** |
| `0x000E` | `SettlementBundle` (`B`) | **2** | `b = H(DSM/settlement-bundle ‖ CCB)` | §5.19 defined; schema 1 burned by 2c-E's transitive bump |
| `0x000F` | `ConsumedDlvTransition` (`T_v`) | 1 | nested in `0x000E` | §5.21 defined |
| `0x0010` | `DlvProofMaterial` (`P_v`) | 1 | nested in `0x000F` | §5.22 defined; zero fields in schema 1 |
| `0x0011` | `TraderAcceptance` (`TA_B`) | 1 | `ta_B = H(DSM/trader-settlement-acceptance/v2 ‖ CCB)` | §5.40 defined by 2c-D |
| `0x0012` | `TradeDigest` | 1 | `d = H(DSM/digest ‖ CCB)` | **blocked, see §6** |
| `0x0013` | `ReferenceWindow` (`{d_i}`) | 1 | `W = H(DSM/ref-window ‖ pair_id ‖ CCB)` | §5.8 defined |
| `0x0014` | ~~`ExternalCommitmentBody`~~ | — | — | **BURNED — §6a finding 3** |
| `0x0017` | ~~`RouteCommitmentBody`~~ | — | — | **BURNED by 2c-F R1** — `X = H_dom(DSM/ext, RC*)` (§2.10); schema 2 never encoded |
| `0x0015` | `Allocation` (`a`) | **2** | leg element; nested in `0x000D` | §5.10 defined; schema 1 **burned** |
| `0x0016` | `AllocationBundle` (`AB_{A→B}`) | **2** | leg element; nested in `0x000D` | §5.11 defined; schema 1 **burned** |
| `0x0018` | **substrate** `GenesisParamsV3` | 1 | `G = H(DSM/genesis/v3 ‖ CCB)` | §5.15 defined |
| `0x0019` | **substrate** `RootProgressionDelegation` (`D_i`) | 1 | `del_i = H(DSM/devtree-delegation ‖ CCB)`, and the GRK-signed bytes | §5.16 defined |
| `0x001A` | **substrate** `DeviceTreeRootTransition` (`T_j`) | 1 | `t_j = H(DSM/devtree-transition ‖ CCB)`, and the delegate-signed bytes | §5.17 defined |
| `0x0031` | **substrate** `DsmSuccessorEvidence` | 1 | `evidence_addr = H(DSM/economic-dsm-successor-evidence/v1 ‖ CCB)`; nested in `0x0033` | §5.23 defined |
| `0x0033` | `MarketTerms` | **2** | nested in `0x000E` | §5.20 defined; schema 1 burned by 2c-E's transitive bump |
| `0x0034` | `SofiReceipt` (Def 14.2 Receipt) | 1 | `ρ_B = H_dom(DSM/sofi-receipt/v1, CCB)` | §5.42 defined by 2c-F |
| `0x001B` | **substrate** `EconomicRootClaimBody` | 1 | signed over `H_dom(DSM/economic-root-claim-sign/v1, CCB)` | §5.24 defined |
| `0x001C` | **substrate** `EconomicAdmissionManifest` | 1 | inner `H_dom(N, P)`; named by `0x001B` field 5 | §5.25 defined |
| `0x001D` | **substrate** `EconomicTransitionWitness` | 1 | inner identity; named by `0x001C` field 2 | §5.26 defined |
| `0x001E` | **substrate** `EconomicLeafMutation` | 1 | nested in `0x001D` | §5.27 defined |
| `0x001F` | **substrate** `EconomicBalanceState` | 1 | leaf state; nested in `0x001E` | §5.28 defined |
| `0x0020` | **substrate** `EconomicVaultReserveState` | 1 | leaf state; nested in `0x001E` | §5.29 defined |
| `0x0021` | **substrate** `EconomicSettlementReceiptState` | 1 | leaf state; nested in `0x001E` | §5.30 defined |
| `0x0022` | **substrate** `EconomicConsumedSourceState` | 1 | leaf state; nested in `0x001E` | §5.31 defined |
| `0x0032` | **substrate** `EconomicBundleAcceptanceState` | 1 | leaf state; nested in `0x001E`; keyed on `economic_operation_id` | §5.41 defined by 2c-D |
| `0x0023` | **substrate** `CreditSourceAuthorizedIssuance` | 1 | credit arm; nested in `0x001D` | §5.33 defined |
| `0x0024` | **substrate** `CreditSourceSameTransitionMove` | 1 | credit arm; nested in `0x001D` | §5.34 defined |
| `0x0025` | **substrate** `CreditSourceValidatedPeerDebit` | 1 | credit arm; nested in `0x001D` | §5.35 defined |
| `0x0026` | **substrate** `CreditSourceDlvReserveConsumption` | **2** | credit arm; nested in `0x001D` | §5.36 defined; schema 1 **burned** |
| `0x0027` | **substrate** `CreditSourceValidatedDlvSettlementPayment` | **2** | credit arm; nested in `0x001D` | §5.37 defined; schema 1 **burned** |
| `0x0028` | **substrate** `CreditSourceVerifiedOfflineReentry` | 1 | credit arm; nested in `0x001D` | §5.38 **STRUCTURALLY FROZEN — BLOCKED ON `0x002D` — BETA REFUSED** |
| `0x0029` | **substrate** `IssuanceAuthorizationBody` | 1 | addressed by `0x0023` field 2 | §5.32 defined |
| `0x0030` | **substrate** `CreditSourceValidatedFaucetDistribution` | 1 | credit arm; nested in `0x001D` | §5.39 defined |
| `0x002A` | **RESERVED** — `OfflineLoadBoundaryBody` | — | — | no field table; no schema |
| `0x002B` | **RESERVED** — `OfflineUnloadBoundaryBody` | — | — | no field table; no schema |
| `0x002C` | **RESERVED** — `OfflineSpendStepEvidence` | — | — | no field table; no schema |
| `0x002D` | **RESERVED** — `OfflineBranchEvidence`; held for the class `0x0028` field 4 addresses | — | — | `0x0028` stays BETA REFUSED until this is promoted and given a preimage |
| `0x002E` | **RESERVED** — `PortableAnchorEnrollmentBody` | — | — | no field table; no schema |
| `0x002F` | **RESERVED** — `PortableHardwareEnrollmentBody` | — | — | no field table; no schema |

`0x0000` reserved. `0x0014` is **burned**: it shipped on `main` as `ExternalCommitmentBody`,
and §6a finding 3 established there is no such object. Re-using that number for
`RouteCommitmentBody` would be exactly the semantic reassignment §2.8 forbids — an assigned
identity does not become vacant just because it never received a field table. `0x0003` is
**burned**: it was briefly assigned to a `StorageMemberId`
object class before members were settled as bare `bytes` under §2.2 — a set of primitives needs no
element class (§2.4), so there was nothing for the number to name. Schema 3 makes the element a
`(member_id, register_incarnation_id)` tuple, which §2.4 does not cover — but §5.2 declares that
tuple's `enc(entry)` inline, so it still needs no class of its own. Per §2.8 a retired class number
is never re-assigned. `0xFF00`–`0xFFFF` reserved for test classes.

**Burned schema versions.** `0x0004`, `0x0005`, `0x000C`, `0x000D`, `0x0015`, `0x0016` and
`0x0017` have schema 1 burned by the state/route identity cut; amendment 2c-F R1 has since burned
`0x000C` and `0x0017` outright. `0x000B`, `0x0033` and `0x000E` have
**schema 1 burned by amendment 2c-E** — `0x000B` because the exact-output cut changed its members,
and the other two transitively, because §2.7 nests by complete CCB. No production path decodes,
accepts, emits or falls back to any of the three, and schema-1 bytes must be refused as **burned**
rather than as an unknown schema. `0x0002` has schemas **1 and 2**
burned, and `0x0001` has schemas **1, 2 and 3** — the second bump on each is the
register-incarnation cut (§5.1, §5.2). They are recorded so their numbers are never re-assigned; no
production path decodes or emits them.

`0x0026` and `0x0027` have **schema 1 burned** by the peer economic-position cut (owner ruling
2026-08-28): schema 1 carried no locator for the peer's validated economic ancestry, and no producer
ever shipped it. **These two rows are the first place that burn is written down.** The shipping
implementation declares it only in a comment beside the class constants; its machine-readable burn
table does not carry either pair, so schema-1 bytes are refused as an *unknown* schema rather than a
*burned* one. Decoding is safe either way — no schema-1 bytes are accepted on any path — but §2.8's
never-re-assign guarantee rests on the burn table, and a later cut that bumps `0x0026` to schema 3
would find no record that schema 1 was ever spent. Recording the two pairs in that table, and a test
that distinguishes the two refusal reasons, are owed by the first implementation change that adopts
amendment 2c-C1.

**Schema bumps are transitive, because nesting is by complete CCB.** §2.7 emits a nested object as
its full CCB *including its own class and schema version*, so changing a nested object's schema
changes the enclosing object's bytes — which §2.8 makes a changed semantics requiring its own new
schema version. The cut therefore propagates upward, and the propagation is mechanical rather than a
judgement call:

```
0x0002 StorageSet   1→2 ─┐
0x0005 EncumbranceSet 1→2─┴─► 0x0001 VaultStateV2  2→3   (fields 14 and 10)
0x0002 StorageSet   2→3 ────► 0x0001 VaultStateV2  3→4   (field 14, register incarnations)
0x000B TradeIntent  1→2 ────► 0x0033 MarketTerms  1→2   (field 1)
                              └─► 0x000E SettlementBundle 1→2   (field 1, the market arm)
0x0015 Allocation   1→2 ─┐
0x0016 AllocBundle  1→2 ─┴─► 0x000D Route          1→2   (leg elements)
                             └─► 0x000C RouteSet    1→2   (set elements)
                                  └─► 0x0017 Q      already 2, unmerged — defined against RouteSet 2
```

The `2→3 ► 3→4` row is the rule demonstrated in production rather than in prospect: making a
storage set commit register incarnations changed `0x0002`'s bytes, which changed every `V_n`
nesting it. It is also why amendment 2c-A's `0x000F` field 2 nests `0x0001` **schema 4** — freezing
a new class against a burned nested schema would ship a non-conformant nesting on day one.

`0x0001` reaching schema 4 is the notable one: schema 3 is burned without ever having been the live
form for a full release, as schema 2 was before it. That is the rule working, not the rule failing — an
object whose nested members changed is a different object, and pretending otherwise is exactly the
silent-divergence §2.8 exists to prevent.

`0x0018`–`0x001A`, `0x001B`–`0x0030` and `0x0031` are **DSM substrate**, not Rev 15 objects. They
are allocated from this table because the namespace is single and indivisible (§2.8), and they carry
the same immutability rules as every other assignment. They are excluded from §4's count and closure
criteria.

The economic block `0x001B`–`0x0030` was absorbed by amendment 2c-C1. Sixteen classes shipped in the
implementation while appearing in no row of this registry — and a namespace the registry cannot see
is a namespace that can be reallocated by accident, which is precisely what §2.8 exists to prevent.
Their field tables are §5.24–§5.39.

### 3.1 Declared enumerations

Enumerations are `u16_be` per §2.2 over values declared here, never over values invented in a field
table. A field table names the enumeration; this section fixes its members.

**`signature_alg`** — identifies a signature algorithm together with the exact encoding of its
public keys and signatures.

| Value | Member | Public key | Signature |
|---|---|---|---|
| `0x0001` | `DSM_BLAKE3_SPHINCS_PLUS_SPX256F` | 64 bytes (`2n`, `n = 32`) | 49,856 bytes |

`0x0001` identifies the exact construction a foreign verifier must implement — its unambiguous
normative designation is **DSM BLAKE3-SPHINCS+-SPX256F**: the SPX256f structure and parameters, with
**DSM's BLAKE3-based hash / PRF / thash construction** in place of SHA2/SHAKE.

**It is not FIPS-205 SLH-DSA-256f.** The public-key and signature widths above coincide *exactly*
with SLH-DSA-256f's, and that coincidence does not make the algorithms interchangeable. An
implementer who reads only the widths, links a standards-conformant SLH-DSA library and verifies a
DSM signature gets a **silent, undiagnosable failure**: every signature is rejected, and no length
mismatch points at why. The member is named for the construction rather than the parameter set so
that this substitution cannot be made by reasonable reading.

Beta declares no other member. The value is committed wherever a public key is, so a future variant
can never be substituted for the committed one.

Widths do **not** identify an algorithm. The committed `signature_alg` value is what binds a key to
its verification procedure; two constructions sharing a parameter set share their sizes and nothing
else. (This replaces an earlier sentence here — *"the algorithm and the key bytes stand or fall
together"* — which was false as written, and false in precisely the direction that made the
substitution above look safe.)

**`authority_role`** — the scope a root-authority delegation confers.

| Value | Member | Meaning |
|---|---|---|
| `0x0001` | `DEVICE_TREE_ROOT_PROGRESSION` | may sign `0x001A` transitions for the named genesis, and nothing else |

Beta declares no other member. A role is deliberately narrow: the GRK exists to delegate one
capability, and a role that meant "may act for the owner" would make the delegation a universal
authority, which the area 8 semantics forbid.

### 3.2 Network parameters

**Normative network parameters.** A verifier resolves these from the authenticated genesis, never
from a candidate object or a catalog:

```text
authenticated genesis  ->  network_id  ->  this table  ->  exact profile
```

**`dsm-testnet` root-register profile.** `network_id = "dsm-testnet"` (ASCII, 11 bytes).

| # | `member_id` | `register_incarnation_id` |
|---|---|---|
| 1 | `dsm-node-1` | `DXWR7W9J2E5ASQ5BJBYF13ZZEK1VFTZFYNWAYPF1KNT8C33YPVM0` |
| 2 | `dsm-node-2` | `H4ZSDG34M1BSQQH8T9WWWZ65Y90YW9QY2CYRR2EG3H621VDGJ3W0` |
| 3 | `dsm-node-3` | `VW3REAWA7PR608Y4AY3VX18M8BE4828PFPNVTG380XV18HKF8SSG` |

```text
n  = 3
q  = 2
storage_set_id = E05YS8101EJH33KY2CG625JJE8A0Z4GJNSEM335TX1XVTWM9RR8G
```

`member_id` is the ASCII name itself, not a digest. `storage_set_id` is
`H_dom(DSM/storage-set, CCB(StorageSet))` over the §5.2 `0x0002` **schema 3** object built from
exactly those three `(member_id, register_incarnation_id)` pairs, in that order. The value is
reproduced here so a foreign verifier can check its own derivation without holding this
repository's build.

**Membership and set id come from one source**, so the two cannot drift apart. This is why `0x0002`
went to schema 3: a set of bare member ids says only *which nodes* a vault trusts, and a member
that rebuilt its register still satisfied it. Pairing each member with its incarnation removes
exactly that ambiguity — **a rebuilt member is a different entry**, so a claim written under the old
incarnation no longer names the set the network resolves to.

**A catalog resolves; it never chooses.** A catalog may say *where* a member is reached and *which*
incarnation it claims. The pinned `storage_set_id` decides whether that is the register the network
actually commits to. Every resolution failure is fail-closed: there is no default register and no
fallback set, because a default register is one an attacker can steer traffic into.

**A network whose identifier has no entry in this table is unknown, not permissive** — verification
refuses.

## 4. Status of this registry

**This registry does not complete every field table, and says so rather than inventing the
missing ones.**

**The counts below did not move when amendment 2c-C1 absorbed `0x001B`–`0x0030`.** All sixteen of
those classes are substrate, excluded from the Rev 15 closure count exactly as `0x0018`–`0x001A` and
`0x0031` are, and the six `0x002A`–`0x002F` entries are reserved rather than classes. Absorbing them
closed a namespace gap; it did not add Rev 15 objects, so a reader should not expect the totals here
to change.

**Nor for 2c-C3**, which decides successor *validity* and adds no class, no encoding and no field
table. **Nor for 2c-C3.1**, whose lineage quarantine is client-local durable state — never
published, never a register value — and allocates nothing here.

**They did not move for 2c-C2 either.** That amendment added the retrieval obligation (§2.11), the
normative network parameters (§3.2) and the one named non-CCB grammar (§2.10), and corrected §3.1's
`signature_alg` member — framework and namespace content, not object classes. No field table was
added, changed or burned.

Of the **twenty-one live** object classes above — `0x0014`, `0x000C` and `0x0017` are burned and
not counted; `0x0033` `MarketTerms` was added by amendment 2c-A and `0x0034` `SofiReceipt` by
amendment 2c-F:

- **18 are fully specified** in §5 — `0x0001`, `0x0002`, `0x0004`, `0x0005`, `0x0007`,
  `0x0008`, `0x0009`, `0x000A`, `0x000B`, `0x000D`, `0x000E`, `0x000F`, `0x0010`,
  `0x0013`, `0x0015`, `0x0016`, `0x0033`, `0x0034`. (Substrate `0x0031` is defined at §5.23 and,
  like `0x0018`–`0x001A`, is **outside** this count.)
- **Encoding closure for the settlement bundle is ACHIEVED.** 2c-B closed `MarketTerms` field 6, so
  a conformant market `b` is constructible; the owner-close shape is encodable once the exact
  prepared `close_authorization` bytes are supplied, and 2c-B freezes the grammar for producing a
  fresh one. Verification closure is **2c-C4's** (the ordered evidence walk, the correspondence and
  the realization predicate); production acceptance of the market shape additionally requires 2c-D's
  bundle-acceptance witness, without which 2c-C4's realization fact is not constructible. 2c-D
  **defines** that witness (§5.41, §5.40); it becomes constructible when 2c-D's adopting change
  ships, not when the amendment freezes.
- **1 is partial** — `0x0006`, where the specification fixes the preimage but `0x0008` is
  still open.
- **1 is blocked** — `0x0012` `TradeDigest`. `0x0011` `TraderAcceptance` was the second until
  amendment 2c-D enumerated its contents (§5.40); it is now defined.

The blocked ones are blocked because the specification names them without ever enumerating
their contents. Writing a field table for those would settle protocol in this document exactly as
writing an encoder first would settle it in Rust. §6 states precisely what each one needs.

The framework in §2 and the namespace in §3 are complete and are **not** blocked on §6.

**Substrate classes are outside this count.** `0x0018`–`0x001A` are DSM substrate, fully specified
in §5.15–§5.17, and they do not enter the twenty-two live Rev 15 classes above. Finding 7 closes on
the Rev 15 amendments in §7 alone; nothing about the substrate classes advances or delays it. The
direction of independence runs both ways — the substrate objects are derivable now, whether or not
`0x0012` ever is.

## 5. Field tables

*(Sections 5.1–5.8 follow the framework above. Objects marked blocked in §3 carry only their
class assignment until §6 is resolved.)*

### 5.1 `VaultStateV2` — class `0x0001`, schema 4

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
| 10 | `encumbrances` (`E`) | nested `0x0005` schema 2 | the encumbrance set, inline by value |
| 11 | `iteration_budget` (`β`) | optional `u64` | §2.3 presence marker; absent is the common case |
| 12 | `parent_state_commitment` (`h_n`) | `digest32` | `c_{n-1}`, or the genesis value at `n = 0` |
| 13 | `owner_authority_transition_digest` (`r_o`) | `digest32` | `t_j = H_dom(DSM/devtree-transition, CCB(T_j))` — the `0x001A` transition under which the owner asserts the device authority signing for this vault |
| 14 | `storage_set` (`S`) | nested `0x0002` schema 3 | inline by value; an ordinary CCB object (§5.2) |
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

**Schemas 1, 2 and 3 are burned.** Schema 1 carried the undefined `owner_root`. Schema 2 defined
field 13 but nested `0x0002` schema 1 and `0x0005` schema 1, so its bytes differ from schema 3's
even though its field *list* is identical — §2.7 nests by complete CCB, including the nested schema
version. **Schema 3 is burned for the same reason one bump later:** it nested `0x0002` schema 2, a
storage set of bare member ids, and the register-incarnation cut makes field 14 a set of
`(member_id, register_incarnation_id)` pairs. The field list did not move; the enclosing bytes did.
Schema 4 is the only decodable form.

This is the §2.8 propagation rule demonstrated in production rather than hypothetically, and it is
why amendment 2c-A's `0x000F` field 2 nests `0x0001` **schema 4**: freezing a new class against a
burned nested schema would ship a non-conformant nesting on day one.

### 5.2 `StorageSet` — class `0x0002`, schema 3

`storage_set_id = H_dom(DSM/storage-set, CCB(S))`, an ordinary CCB object with no exceptions.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `entries` | set of `(member_id: bytes, register_incarnation_id: digest32)` | ordered by `member_id` **alone**, never by the pair — see below |

**The element encoding is declared here, because §2.4 does not cover it.** §2.4 defines `enc(e)`
for an object class (complete CCB) and for a primitive (§2.2), and a tuple is neither. For this
field:

```text
enc(entry) = u32_be(len(member_id)) ‖ member_id ‖ register_incarnation_id
```

— the two primitive encodings concatenated, with no element envelope, because the pair has no
object class of its own. The whole field is therefore

```text
u32_be(count) ‖ enc(entry_1) ‖ … ‖ enc(entry_count)
```

An empty set, an empty `member_id`, a duplicate `member_id` and an all-zero
`register_incarnation_id` are each invalid.

**Ordering is by `member_id` alone, and this is a deliberate departure from §2.4's default.**
Sorting on the whole entry would let one member appear twice under two incarnations and still
produce a strictly ascending list — exactly the ambiguity schema 3 exists to remove. A duplicate
`member_id` is therefore refused *regardless of incarnation*.

**The pinned instantiation lives in §3.2.** That table carries the exact
`(member_id, register_incarnation_id)` pairs, `n`, `q` and the derived `storage_set_id` for each
network, so the element encoding frozen here and the values it is instantiated with can be read
against one another. A network absent from §3.2 is unknown, not permissive.

An all-zero incarnation is refused because that is the value a member holds before it has
established one; committing it would bind a vault to "whatever this node had not yet decided".

**Schemas 1 and 2 are burned.** Schema 2 is burned by the register-incarnation cut: a set of bare
member ids says only *which nodes* a vault trusts, and a member that rebuilt its register still
satisfied it. Schema 3 commits which register histories the set trusts, so field 1 is a set of
`(member_id, register_incarnation_id)` pairs rather than bare identity strings. That bump forced
`0x0001` from schema 3 to schema 4 (§5.1).

**Schema 1 is burned too — it was the registry's largest explicit legacy encoding.** It froze the
shipping `sdk/storage_set.rs` layout: no §2.1 envelope, bare length-prefixed elements instead of
`enc(e)`, and a preimage beginning with the domain tag rather than
`u16_be(class) ‖ u16_be(version)`. It said of itself that it "must not be 'cleaned up'".

That freeze existed for exactly one reason, stated in its own text: **"every deployed vault's signed
anchor already commits a `storage_set_id` under this construction, and adopting the framework would
invalidate all of them."** The state-identity cut deletes those anchors and reprovisions, so no
deployed signature depends on the layout any more. The rationale is void, and keeping the encoding
after its reason has gone would be legacy preserved by habit — while this document claims no legacy
anywhere.

Class `0x0003` remains burned: it was briefly assigned to a `StorageMemberId` object before members
were settled as bare strings, and schema 3 does not revive it — the element is now a tuple whose
`enc(entry)` this section declares inline, so it needs no class of its own.

### 5.3 `EncumbranceClaim` — class `0x0004`, schema 2

`e_j = H(DSM/enc-claim ‖ p ‖ claim_seq ‖ amount ‖ token ‖ purpose)`, where `p` is the `c_n` of the
DLV parent state the claim is made against.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `parent_binding` | `digest32` | the `p` of the claim — `c_n`, never the deleted `h_n` projection |
| 2 | `claim_seq` | `u64` | |
| 3 | `amount` | `u64` | base units; §3.4 fixed-point applies to derived ratios, not to this field |
| 4 | `token` | `digest32` | token policy commitment |
| 5 | `purpose` | `u16` | enumeration; values are declared where the purpose set is defined |

**Schema 1 is burned.** It carried `vault_id` alongside a `parent_state_commitment` documented as
`h_n` — the old parent model surviving through the accounting path, which is the least visible place
for it to survive. Schema 2 pins the parent to `c_n` and drops `vault_id`, which `c_n` commits.

#### `parent_binding` is the CREATION parent, and this is what keeps the encoding acyclic

`E` is a member of `V_n`, so a claim is nested inside the very state whose identity is `c_n`. Reading
"the claim's parent is `c_n`" as *the containing state's* `c_n` would give

```
c_n → CCB(V_n) → E_n → e_j → c_n
```

— a hash fixed point, which no encoder can compute and no verifier can check. The rule is therefore
stated in transition terms and is not optional:

> If the transition `V_n → V_{n+1}` creates claim `e_j`, then `e_j.parent_binding = c_n` — the
> identity of the state the transition consumed — and `e_j` is inserted into `E_{n+1}`. If the claim
> persists across later successors it is carried **byte for byte**; its `parent_binding` is never
> rewritten to the containing state's `c_k`.

Every claim inside `E_{n+1}` therefore binds a `c_k` with `k ≤ n`, all of them already computed when
`c_{n+1}` is formed. The preimage is finite and the dependency graph runs strictly backwards.

The "carried byte for byte" half is the part an implementation is likely to get wrong, because
refreshing a claim's parent to the current state looks like bookkeeping hygiene. It is the cycle.

`EncumbranceSet` — class `0x0005`, schema 2 — is a set of `EncumbranceClaim` under §2.4. It is
nested by value in `0x0001` field 10 and **no longer feeds a standalone digest**: the derived
per-vault commitment `EC_v` is deleted, because `c_n` commits the set already. Schema 1 is burned
with the claim schema it contained.

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

### 5.5 `TradeIntent` — class `0x000B`, schema 2

Amended by **2c-E** to the shipped exact-output market model.
`TradeIntent = {token_in, amount_in, token_out, exact_out, fee_bps, nonce}`. No expiry, timestamp or
duration is permitted; §9.1 of the specification excludes them and §2.8 forbids extending a shipped
schema version.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `token_in` | `digest32` | input token policy commitment |
| 2 | `amount_in` | `u64` | base units; checked narrowing from the signed 16-byte wire value, a value exceeding `u64` is a refusal and never a truncation |
| 3 | `token_out` | `digest32` | output token policy commitment |
| 4 | `exact_out` | `u64` | base units — the exact output the trader signed. NOT a floor |
| 5 | `fee_bps` | `u32` | the fee **rate** the trader signed. Base units are not carried: the fee in base units is a function of the amount and the rate, and a second representation could disagree with its own inputs |
| 6 | `nonce` | `digest32` | the trader's replay binding |

No field 7.

**Schema 1 is burned.** It carried `min_out`, `max_fee`, `max_hops`, `max_fanout` and `k` — members
of a model `RouteCommit` v2 deleted when it removed slippage floors and pre-signed fallbacks for
*"one route, one anchored state, one exact output, one signature"*. Four of them had no wire source
at all, so a producer could only have invented them, and `I` would then commit to values no verifier
could re-derive. What each dropped member protected, and what protects it now, is tabulated in
amendment 2c-E §5.

**"The selected route satisfies `I`"** is stated normatively in 2c-E §6 (`SAT.1`–`SAT.6`), replacing
the prose amendment 2c flagged. The load-bearing clause is `SAT.5`: `exact_out` is checked by
re-simulating the market policy against the **authenticated** `V_n` that `c_n` names, never against
the route's own account of itself — otherwise the predicate would be a self-attestation of the
selected route.

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

Def 9.1: `a = (parent_binding, Δ_in, Δ_out, e, Φ)`.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `parent_binding` | `digest32` | `c_n = H_dom(DSM/vault-state, CCB(V_n))` — the exact complete current state |
| 2 | `delta_in` | `u64` | base units into the DLV |
| 3 | `delta_out` | `u64` | base units out of the DLV |
| 4 | `encumbrance_claim` (`e`) | `digest32` | the single claim this allocation consumes, `e_j` of §8 |
| 5 | `fee_policy` (`Φ`) | nested `0x000A` | inline by value |

**`vault_id` is not a member.** `c_n` commits it, because `vault_id` is a field of `V_n`. Carrying
both would admit an encodable `(vault_id, c_n)` pair that disagrees — one naming a vault, the other
naming a state belonging to a different one. A verifier resolves `V_n` from `c_n` and reads the
authoritative identifier there.

No token pair: `c_n` commits `P_M`, which commits the pair.

**Schema 2 replaces `p_v` with `c_n`, and schema 1 is burned.** The reason is not that `p_v`
duplicated anything — normatively it is a single digest. It is that `p_v` commits only a *selected
projection* of `V_n` (vault id, generation, the predecessor edge `h_n`, the reserves digest, `S`,
`q`), whereas `c_n` commits the **exact complete current state**. A parent identity that omits parts
of the parent is a parent identity that cannot detect changes in the parts it omits.

### 5.11 `AllocationBundle` — class `0x0016`, schema 2

Def 9.2: `AB_{A→B} = {a_1,…,a_f}`, `1 ≤ f ≤ max_fanout`, every member converting the same
input token to the same output token and naming a **distinct** DLV.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `allocations` | set of `0x0015` | §2.4 ordering over complete element CCB |

`max_fanout` is **not** a field — it is authoritative in `TradeIntent` field 7, and the member
count is checked against it.

**Schema 2 canonicalizes by complete Allocation CCB, and schema 1 is burned.** Schema 1's ordering
argument depended on `vault_id` being field 1 of the element, so that ordering by element CCB *was*
ordering by vault id. Schema-2 `Allocation` has no `vault_id`, so that argument no longer holds and
is not patched — the set is ordered by the whole element under §2.4, which is well-defined without
it.

**Distinct-DLV is checked against the bound states, not against a carried identifier.** Two members
are distinct DLVs when the `vault_id` values recovered from their bound `V_n` differ. Retaining a
duplicate identifier inside the allocation purely to preserve a sorting explanation would be the
alias this cut removes.

### 5.12 `RouteCommitmentBody` — class `0x0017` — **BURNED by 2c-F R1**

> **Burned 2026-09-11.** The shipped `X` is `H_dom(DSM/ext, RC*)` over the signed RouteCommit that
> `B` carries (§2.10), so no `Q` object exists and nothing encodes this class at any schema. What
> follows is the record of what was defined, not a live layout.

`X = H(DSM/route-set ‖ CCB(Q))`. Replaces the four-operand concatenation of §9.3.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `intent` (`I`) | `digest32` | `H(DSM/intent ‖ CCB(TradeIntent))` |
| 2 | `route_set` (`R`) | nested `0x000C` schema 2 | inline by value |
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

### 5.13 `Route` — class `0x000D`, schema 2

§9.3: "A route is a sequence of logical legs, each leg being either a one-vault allocation or
a same-pair allocation bundle", `r_i = ⟨A_{i,1},…,A_{i,h}⟩`, `h ≤ max_hops`.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `legs` | **sequence** of `0x0015` \| `0x0016`, both schema 2 | §2.5 ordering — emitted in route order, **never sorted** |

**Schema 2, schema 1 burned.** Both leg classes moved to schema 2 and legs nest by complete CCB, so
this object's bytes changed even though its single field did not.

One field, deliberately. `max_hops` is not carried — and since 2c-E it is not a `TradeIntent`
member either: schema 1, which carried it, is burned. The beta route is exactly one leg (2c-A ruling
3), and what now protects each dropped bound is 2c-E §5's. *(Corrected by 2c-F finding I-1: this
sentence cited `TradeIntent` field 6, which is `nonce` in schema 2.)*

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

### 5.14 `RouteSet` — class `0x000C` — **BURNED by 2c-F R1**

> **Burned 2026-09-11.** One signature binds one route, so the committed route set is the singleton
> selected route and no `R` object exists. What follows is the record of what was defined, not a
> live layout. Its reference to `TradeIntent` field 8 was stale even before the burn: schema 2 has
> no field 8 (2c-F finding I-1).

§9.3: `R = {r_1,…,r_k}`, "canonicalized by route CCB ascending", with `k` bounded by
`TradeIntent.k`.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `routes` | set of `0x000D` schema 2 | §2.4 ordering over complete `Route` CCB; duplicates invalid |

**Schema 2, schema 1 burned.** `Route` moved to schema 2, and this set nests complete `Route` CCB,
so its own bytes changed. Nothing else about it did.

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

---

*Sections 5.19–5.22 are frozen by
[amendment 2c-A](amendment-2c-a-bundle-and-transition.md), which carries the reasoning, the
seven owner rulings and the full verification obligations. This registry supplies their bytes.*

### 5.19 `SettlementBundle` — class `0x000E`, schema 2

`b = H_dom(DSM/settlement-bundle, CCB(SettlementBundle))`, and `tx_id = value_digest = b`.

> **Encoding closure ACHIEVED for both shapes.** `MarketTerms.recovery_material` (§5.20 field 6)
> nests `0x0031` schema 1 per [2c-B](amendment-2c-b-accepted-successor-and-recovery.md), so a
> conformant market `b` is constructible. The **owner-close** shape carries no `MarketTerms` and is
> encodable **once the exact prepared `close_authorization` bytes are supplied** — 2c-B freezes the
> foreign grammar needed to construct and verify a fresh one.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `market_terms` | optional nested `0x0033` schema 2 | §2.3 presence marker always emitted; present **iff** Market. This is the bundle-shape discriminator |
| 2 | `transitions` (`{T_v}`) | set of `0x000F` schema 1 | §2.4 over complete element CCB; duplicates invalid; **beta cardinality exactly 1** |

**Shape rule.**

```text
Market:      market_terms PRESENT, |{T_v}| == 1 (beta), every T_v.close_authorization ABSENT
OwnerClose:  market_terms ABSENT, |{T_v}| == 1, that T_v.close_authorization PRESENT
otherwise:   INVALID
```

The discriminator is field 1, so a decoder knows the shape immediately after the first field and
never has to inspect a later transition to decide whether an earlier optional field was legal.

**No `storage_set_id`, no `q`, no `vault_id`.** Binding authority comes from the authenticated
consumed parent: resolve `T_v.parent_binding = c_n` to `V_n`, then `S = V_n.storage_set` and
`q = V_n.quorum` (fields 14 and 15). Bundle validity separately requires
`V_{n+1}.storage_set == V_n.storage_set` and `V_{n+1}.quorum == V_n.quorum`. The proposed successor
is never authoritative for its own quorum. `vault_id` lives inside the nested `V_n`/`V_{n+1}`, where
it is authoritative, and is not restated beside a commitment that already commits it.

**Vault uniqueness** holds without a carried identifier: `k_v = H_dom(DSM/binding-keyset,
T_v.parent_binding)`, `K(B)` admits no duplicate `k_v` (Def 6.17), and §18.5 says a
bound-but-unrealized market settlement does not advance the parent — so two transitions on one DLV
would claim the same `c_n` and collide.

**A first ship, not a burn.** `0x000E` never had a defined CCB schema; the shipping implementation
hashes protobuf bytes, which §2.10 says is never a CCB blob. No current identifier is a conformant
`b`.

> **Corrected 2026-09-09 by the 2c-A.1 adopting change (#799).** The present tense above is the
> pre-cut record. The encoder shipped, the protobuf bundle was deleted, and every `b` is now
> `H_dom(DSM/settlement-bundle, CCB(B))` over canonical bytes. No prost-era identifier is
> grandfathered — the cut is a reprovision (2c-A.1 ruling 4), owed at deployment.

### 5.20 `MarketTerms` — class `0x0033`, schema 2

Everything a market settlement has and an owner close does not. Nested by value in `0x000E` field 1
and never separately content-addressed, so it adds **no entry to §15.8's canonical immutable-object
inventory** — the same footing as `MarketPolicy`, `FeePolicy`, `Route` and `TradeIntent`.

> **Encoding closure ACHIEVED.** Field 6 nests `0x0031` schema 1, fixed by
> [amendment 2c-B](amendment-2c-b-accepted-successor-and-recovery.md). Verification closure is
> **2c-C4's**; production acceptance of the market shape stays gated on 2c-C3's `ValidDlvSuccessor`
> and on 2c-C4's realization fact, whose final conjunct only 2c-D can supply. **2c-D supplies it**
> — the bundle-acceptance leaf `0x0032` (§5.41) and `TA_B` (§5.40) — so the gate is now on that
> amendment's adopting change rather than on an unwritten document.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `intent` | nested `0x000B` schema 2 | the complete `TradeIntent`; `I = H_dom(DSM/intent, CCB(field 1))` is **derived, never carried** |
| 2 | `route_set_commitment` (`X`) | `digest32` | `H_dom(DSM/ext, RC*)` (2c-F R1, §2.10); `RC` itself rides in field 6's `operation_bytes` (`DlvSettleOperationPreimageV1` field 9) |
| 3 | `selected_route` (`r`) | nested `0x000D` schema 2 | the complete executed route, inline by value |
| 4 | `trader_parent` | `digest32` | exact ordinary-DSM bilateral parent-state commitment |
| 5 | `trader_successor` | `digest32` | exact prepared `C_dsm+` |
| 6 | `recovery_material` | **mandatory** nested `0x0031` schema 1 | non-secret canonical material reconstructing exactly `trader_parent → trader_successor`; see §5.23 |

**Field 6 is mandatory, not optional-with-a-rule.** A market settle is not reconstructible from
`C_dsm+` alone — the route-commit preimage, signature material and entropy are not
composer-derivable — so a market bundle that became binding-final without it would be
unrecoverable after a crash. Placing the optionality at the subobject boundary makes a market
bundle without recovery material **unencodable** rather than merely invalid. An owner close has no
`MarketTerms` and therefore no such slot.

**`I` is the object, not a digest**, because a `digest32` has no `token_in`, `amount_in`, `min_out`
or `max_fee`, and the route-satisfaction predicate must be discharged from the bundle. `I` and `X`
are never aliases: they commit different objects under different domains.

**`0x0033` comes from a namespace audit.** `0x0001`–`0x0030` is contiguously allocated or reserved
with no usable vacancy (`0x0003` and `0x0014` burned; `0x002A`–`0x002F` structurally reserved);
`0x0031` and `0x0032` were claimed by amendment 2c for 2c-B and 2c-D, and both have since been
allocated by them (§5.23, §5.41). The registry §3 table was
**behind the shipped code** for the economic classes in `0x001B`–`0x0030` when this audit ran;
amendment 2c-C1 has since recorded all sixteen, with the six reserved numbers, so §3 and the
implementation now agree across the whole block.

### 5.21 `ConsumedDlvTransition` — class `0x000F`, schema 1

Def 6.14's prose governs: the parent side is the exact `c_n` and nothing else — no vault
identifier, parent generation, `h_n` or parent reserves digest, because each is a field of `V_n`.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `parent_binding` (`c_n`) | `digest32` | the exact consumed DLV state commitment |
| 2 | `successor` (`V_{n+1}`) | nested `0x0001` schema 4 | the **complete proposed successor state**; `c_{n+1} = H_dom(DSM/vault-state, CCB(field 2))` is derived |
| 3 | `proof_material` (`P_v`) | optional nested `0x0010` schema 1 | §2.3; absent throughout the beta profile |
| 4 | `close_authorization` | optional `bytes` | present **iff** owner close; a signature over the canonical DSM close-operation preimage (2c-B) |

Never carry both field 2 and a separate `c_{n+1}` digest.

**The parent/successor asymmetry is deliberate.** The parent is referenced because it already
exists as realized authoritative state, is independently authenticated, and is the input to `k_v`.
The successor is *completely specified before binding but is not yet authoritative realized state*
— `B` commits a proposed exact successor, and realization decides whether it becomes economic
state. A digest-only successor would send a verifier to fetch a preimage that no authoritative
source publishes before realization.

**Reserve deltas are not carried.** `V_n` and `V_{n+1}` each commit their own reserves, so the
movement is their difference; the route's `Allocation.delta_in`/`delta_out` already states the
quantities once.

**Structural checks 2c-A owns**, computable from the bundle plus the authenticated parent:

```text
V_{n+1}.parent_state_commitment == T_v.parent_binding     (no fetch — field 12 of 0x0001)
V_{n+1}.generation              == V_n.generation + 1
V_{n+1}.storage_set             == V_n.storage_set
V_{n+1}.quorum                  == V_n.quorum
OwnerClose: V_{n+1}.reserve_a == 0 and V_{n+1}.reserve_b == 0
```

The full `ValidDlvSuccessor(V_n, V_{n+1}, operation)` relation — every preserved field, every
permitted mutation — is **2c-C3's**, which froze it (`ValidDlvSuccessorCore`; `TokenPolicyValid`
stays external per its ruling H). Constant-product re-simulation proves reserve arithmetic and
nothing else; field 13 `owner_authority_transition_digest`, for instance, is invariant across a
market successor and no arithmetic check would notice it moving.

**Field 4 is the per-transition authorization marker, not the bundle-shape discriminator** (that is
`0x000E` field 1). Validity requires the two to agree. §2.9 is not violated: field 4 signs a
*foreign* object, so the ordering is total — sign the operation, encode `T_v`, encode `B`, compute
`b`. Only the signature is carried; the operation is reconstructed from `V_n` and `V_{n+1}`.

### 5.22 `DlvProofMaterial` — class `0x0010`, schema 1

**Zero fields.** For beta's only declared pricing family — `CONSTANT_PRODUCT_EXACT_INPUT`,
`family_version = 1` — a verifier holding the authenticated `V_n`, the complete `V_{n+1}`, the
selected route and its `Allocation` already has every fact. No irreducible witness material
remains, and none is manufactured to populate the type.

The bare envelope is 4 bytes and is defined, but beta always encodes `0x000F` field 3 as absent, so
it never appears on the wire.

**A future proof form does not come free.** A nested object's complete CCB includes its schema
version, so `0x0010` schema 2 forces a `0x000F` bump, which forces a `0x000E` bump. Field 3 buys a
permanently assigned slot and semantic role, not immunity from enclosing-schema propagation.

### 5.23 `DsmSuccessorEvidence` — class `0x0031`, schema 1

**Substrate**, on the same footing as `0x0018`–`0x001A`: allocated from the single namespace,
carrying the same immutability rules, and excluded from §4's Rev 15 closure count. Frozen by
[amendment 2c-B](amendment-2c-b-accepted-successor-and-recovery.md), which carries the reasoning
and the four owner rulings.

`evidence_addr = H_dom(DSM/economic-dsm-successor-evidence/v1, CCB(DsmSuccessorEvidence))` —
over the **canonical CCB bytes**, never over protobuf. Protobuf remains transport only.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `rel_key` | `digest32` | not derivable from `B`: `DevID = H(DSM/devid ‖ AK_pk ‖ AttA)`, and `AttA` is nowhere in the bundle |
| 2 | `embedded_parent` | `digest32` | must equal `B.market_terms.trader_parent`; carried so the equality is checked, not assumed |
| 3 | `counterparty_devid` | `digest32` | same `AttA` problem; a settle is a self-loop, so this is the trader's own DevID |
| 4 | `operation_bytes` | `bytes` | a `DlvSettleOperationPreimageV1` — a **foreign** grammar frozen by 2c-B, carried opaquely here |
| 5 | `entropy` | `bytes`, **exactly 32** | `H_dom(DSM/state-entropy, prior_entropy ‖ op_bytes ‖ prior_hash)`. Any other length is invalid |
| 6 | `encapsulated_entropy` | optional `bytes` | always **absent** in this profile; the chain-tip preimage distinguishes absent from present-and-empty, so absence is encoded per §2.3, never flattened |
| 7 | `sigma_dsm` | `bytes`, **exactly 49,856** | one `SPHINCS_PLUS_SPX256F` signature (§3.1) over `H_dom(DSM/economic-substrate-sign/v1, G ‖ DevID ‖ C_dsm+ ‖ operation_digest)`. Any other length is invalid |

**`c_dsm_plus` is not a field.** It is doubly derivable — `relationship_chain_tip_v2` recomputes it
from the six inputs, and it equals `B.market_terms.trader_successor` — so carrying it would state
one fact three times. The existing verifier already recomputes rather than trusting a carried value.

**CCB field numbers are their own namespace** (§2.10) and need not agree with the transport
message's, so `sigma_dsm` is field 7 here and field 8 there. The gap is deliberate, not an omission.

**Two nested foreign grammars, and one endianness trap.** `operation_bytes` and `0x000F` field 4's
signature preimage are hand-rolled encodings frozen by 2c-B, carried by CCB but not *being* CCB —
which §2.10 permits. They use **little-endian** length prefixes and length-prefix their 32-byte
values, both the opposite of CCB's big-endian `u32` and bare `digest32`. Separate preimages, not a
contradiction; an implementation that conflates them produces different bytes for the same object.

**Validity.** A market bundle's field 6 must decode, re-encode to itself, and satisfy the
encoding-level conjunct on `operation_bytes` **before** the chain-tip equalities against
`B.market_terms.trader_successor` and `.trader_parent`. 2c-B states both, in that order, and
performs no other cross-object comparison — everything further is `ValidDlvSuccessor`, owned by
2c-C3.

### 5.24 `EconomicRootClaimBody` — class `0x001B`, schema 1

Signed. Per §2.9 the signature is **not** a field: it travels in the protobuf carrier
`EconomicRootClaimV1 { body_ccb, claimant_signature }` over
`m = H_dom(DSM/economic-root-claim-sign/v1, CCB)`. Protobuf is carrier only — the signed preimage is
the domain hash of the CCB, never the transport bytes (§2.10).

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

### 5.25 `EconomicAdmissionManifest` — class `0x001C`, schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `authority_position` | `digest32` | a transition digest, never a counter |
| 2 | `transition_witness_addr` | `digest32` | inner identity of `0x001D` |
| 3 | `authority_evidence_addr` | `digest32` | |
| 4 | `substrate_dsm_successor` | optional `digest32` | **mutually exclusive with field 5** |
| 5 | `substrate_offline_boundary` | optional `digest32` | **mutually exclusive with field 4** |
| 6 | `provenance_evidence_addrs` | set of `digest32` | §2.4 count prefix; sorted ascending by the raw 32 bytes; duplicates invalid |

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

### 5.26 `EconomicTransitionWitness` — class `0x001D`, schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `pre_economic_root` | `digest32` | |
| 2 | `post_economic_root` | `digest32` | must equal the root the mutations derive |
| 3 | `economic_operation_id` | `digest32` | |
| 4 | `operation_digest` | `digest32` | binds the witness to the local acceptance |
| 5 | `mutations` | sequence of nested `0x001E` | §2.5 count prefix; **count ≥ 1** |
| 6 | `credit_sources` | sequence of nested union `{0x0023, 0x0024, 0x0025, 0x0026 s2, 0x0027 s2, 0x0028, 0x0030}` | §2.5 count prefix; **strictly ascending by `credit_mutation_index`** |

**Field 6's ordering predicate is declared here, because §2.4 cannot state it.** §2.4 orders a set
ascending by `enc(e)`, and `enc(e)` for a credit source begins `u16 class ‖ u16 schema`, so `enc(e)`
order is *(class, schema, index…)* — which differs from index order whenever two elements have
different classes. Field 6 is therefore a §2.5 **sequence** whose order is constrained by this table
rather than by the framework: strictly ascending `credit_mutation_index`, which also forbids
duplicates without needing set semantics.

**Field 6's element type is a union of seven classes**, discriminated by the §2.1 envelope exactly as
§2.5's heterogeneous-sequence rule intends — no in-band tag.

### 5.27 `EconomicLeafMutation` — class `0x001E`, schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `pre_state` | optional nested union `{0x001F, 0x0020, 0x0021, 0x0022}` | |
| 2 | `post_state` | optional nested union `{0x001F, 0x0020, 0x0021, 0x0022}` | **not both absent** |
| 3 | `siblings` | **exactly 256 × `digest32`, no count prefix** — 8192 raw bytes | declared here; see below |

The three legal combinations are *(absent, present)* insert, *(present, present)* update, and
*(present, absent)* delete. Where both are present their **position material must agree** — the class
and identifying digests of a leaf cannot change under a mutation of that leaf.

**Field 3's encoding is declared here, because §2.2 has no array type and both §2.4 and §2.5 mandate
a `u32_BE` count.** The count is not carried because it is not free: it is fixed at 256 by the tree
the proof is against. Emitting it would be a second, settable statement of a constant — the alias
pattern this registry removes. A decoder reads exactly 256 digests and never reads a count; any other
length is invalid. This is the same in-table mechanism §5.2 uses for its tuple element, and it needs
no §2 change.

### 5.28 `EconomicBalanceState` — class `0x001F`, schema 1

44 bytes. Envelope plus scalars: no optionals, no sets, no sequences, no nesting.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `policy_commit` | `digest32` | |
| 2 | `amount` | `u64` | **must be non-zero** — enforced in both the constructor and the encoder |

### 5.29 `EconomicVaultReserveState` — class `0x0020`, schema 1

84 bytes.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `vault_id` | `digest32` | |
| 2 | `policy_commit` | `digest32` | |
| 3 | `amount` | `u64` | **zero is legal and meaningful** — the terminal drained-vault state |
| 4 | `vault_sequence` | `u64` | |

**The `0x001F`/`0x0020` zero asymmetry is real and load-bearing, and this registry states it rather
than normalising it.** A zero *balance* is leaf-**absent**: it has no canonical bytes, so encoding one
would create a second representation of absence. A zero *reserve* is leaf-**present** at a stated
`vault_sequence`: it is the terminal state of a closed vault, and erasing it would erase the fact
that the vault was drained rather than never funded.

### 5.30 `EconomicSettlementReceiptState` — class `0x0021`, schema 1

196 bytes.

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

### 5.31 `EconomicConsumedSourceState` — class `0x0022`, schema 1

68 bytes.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `source_id` | `digest32` | |
| 2 | `consumer_economic_operation_id` | `digest32` | attribution — what turns a bare "spent" flag into a statement of *who* spent it |

### 5.32 `IssuanceAuthorizationBody` — class `0x0029`, schema 1

148 bytes.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `policy_commit` | `digest32` | |
| 2 | `issuer_genesis` | `digest32` | |
| 3 | `issuer_devid` | `digest32` | |
| 4 | `issuer_economic_position` | `u64` | |
| 5 | `recipient_operation_digest` | `digest32` | |
| 6 | `amount` | `u64` | **valid domain `1 ..= 2^64 − 1`; zero is invalid** (amendment 2c-C1 ruling C) |

### 5.33–5.39 the credit sources — classes `0x0023`–`0x0028` and `0x0030`

Seven arms, discriminated by the §2.1 envelope class — there is no in-band tag. Field 1 of every arm
is `credit_mutation_index : u32`, the index into the enclosing witness's `mutations` sequence, and
the enclosing `0x001D` field 6 requires those indices to be strictly ascending across the sequence.

Every `*_addr` field below carries the **inner** identity `H_dom(N, P)`, never the outer
storage-object address (amendment 2c-C1 ruling A).

**§5.33 — `0x0023 CreditSourceAuthorizedIssuance`**, schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `credit_mutation_index` | `u32` | |
| 2 | `issuance_authorization_addr` | `digest32` | addresses `0x0029` |

**§5.34 — `0x0024 CreditSourceSameTransitionMove`**, schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `credit_mutation_index` | `u32` | **must differ from field 2** |
| 2 | `debit_mutation_index` | `u32` | a transition cannot fund itself from itself |

**§5.35 — `0x0025 CreditSourceValidatedPeerDebit`**, schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `credit_mutation_index` | `u32` | |
| 2 | `peer_genesis` | `digest32` | |
| 3 | `peer_devid` | `digest32` | |
| 4 | `peer_economic_position` | `u64` | **untrusted locator** — the verifier derives the position independently |
| 5 | `peer_debit_mutation_index` | `u32` | indexes the **peer's** witness, not this one |
| 6 | `acceptance_evidence_addr` | `digest32` | |

**§5.36 — `0x0026 CreditSourceDlvReserveConsumption`**, **schema 2** (schema 1 burned)

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `credit_mutation_index` | `u32` | |
| 2 | `vault_id` | `digest32` | |
| 3 | `parent_sequence` | `u64` | |
| 4 | `x` | `digest32` | |
| 5 | `owner_economic_position` | `u64` | **the schema-2 field** — an untrusted locator |
| 6 | `reserve_consumption_evidence_addr` | `digest32` | |

**§5.37 — `0x0027 CreditSourceValidatedDlvSettlementPayment`**, **schema 2** (schema 1 burned)

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

**Producer (amendment 2c-G).** The owner's catch-up builds the `SettlementPaymentEvidenceV1`
bundle (transport proto, no CCB class) from the certified fold: the exact `0x0021` leaf and
256-sibling path the composition walk proved under the trader's validated `R_T^+` at the
acceptance's position (Req 21.16), carried on the fold and never fetched again. Fields 5–7 are the
walk's authenticated trader and that position. The producer mirrors the arm's leaf-equality and
inclusion checks before signing — the arm runs after the advance commits, where a refusal would
strand the admission — and the arm alone decides. `DlvOwnerApplyV2` is admission-fenced at the
core chokepoint: an owner apply is admitted with this arm or it does not advance.

**Two schema-2 arms, one reason.** Both carry a peer/owner `*_economic_position` that schema 1 did
not, and both are labelled **untrusted locators**: they say where to start looking, never what is
true. The verifier derives the position independently. That is the same locator-not-authority
distinction amendment 2c-A applied to `trader_parent`.

**§5.38 — `0x0028 CreditSourceVerifiedOfflineReentry`**, schema 1 —
**STRUCTURALLY FROZEN — BLOCKED ON `0x002D` — BETA REFUSED**

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `credit_mutation_index` | `u32` | |
| 2 | `prior_boundary_id` | `digest32` | **must differ from field 3** |
| 3 | `unload_boundary_id` | `digest32` | |
| 4 | `branch_evidence_addr` | `digest32` | **no defined preimage** — addresses reserved class `0x002D` |

The field table is frozen and the class is refused in beta. Field 4 addresses a class that does not
exist: `0x002D` is reserved, has no field table and no preimage, so nothing a verifier could fetch at
that address has defined bytes. Freezing the structure is what lets the number and the field list
stop moving; refusing the arm is what keeps an undefined edge out of production. `0x0028` leaves this
state only when `0x002D` is promoted to a class with a preimage — a normative registry change.

**§5.39 — `0x0030 CreditSourceValidatedFaucetDistribution`**, schema 1

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `credit_mutation_index` | `u32` | |
| 2 | `faucet_id` | `digest32` | must equal the derived canonical faucet identity |
| 3 | `ticket_index` | `u64` | |
| 4 | `faucet_claim_evidence_addr` | `digest32` | **inner form** per ruling A — the shipped code emits the outer form and must change |

### 5.40 `TraderAcceptance` — class `0x0011`, schema 1

**8,308 bytes** — 4 envelope + 32 `G` + 8 position + the 68-byte nested `0x0032` + 4 sequence
count + 256×32 siblings. `ta_B = H_dom(DSM/trader-settlement-acceptance/v2, CCB(TA_B))`. The `/v2` is the
tag Rev 15 reserves for this artifact and is **not** a schema version.

Frozen by [amendment 2c-D](amendment-2c-d-bundle-acceptance-and-realization.md). This is a **first
freezing, not an amendment to frozen bytes**: the class has never been produced, so no schema is
burned. It supersedes the nine-field draft in amendment 2c §2, which §7a of that document had
already reassigned here for re-derivation.

The artifact carries no signature of its own — SoFi adds no acceptance payload and no signing round
— so §2.9 applies vacuously.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `trader_genesis` (`G`) | `digest32` | **carried authenticated witness.** Not recoverable from `b`; authenticated by reconstructing the `sigma_dsm` signing digest and verifying it under the independently established trader AK. Never authority before that check |
| 2 | `economic_position` | `u64` | **untrusted locator.** Where to begin the validity walk, never authority for its result |
| 3 | `acceptance_leaf` (`L_B`) | nested `0x0032` schema 1 | complete CCB per §2.7 |
| 4 | `acceptance_path` (`π_B`) | **sequence** of `digest32` | exactly 256 siblings, leaf-to-root; a §2.5 sequence because position is tree depth and duplicates are legal |

**No field 5.** Five members of the superseded draft are gone, for two distinct reasons:

```text
recoverable from the authenticated bundle b
    route_set_commitment (X)   MarketTerms.route_set_commitment
    trader_parent              MarketTerms.trader_parent
    trader_successor           MarketTerms.trader_successor
    trader_devid               operation_bytes.settler_devid — a field of the
                               frozen DlvSettleOperationPreimageV1 grammar that
                               G1 decodes and G2 re-encodes canonically

recoverable from the authenticated acceptance leaf
    bundle (b)                 acceptance_leaf.bundle
```

`trader_devid` is **not** taken from `recovery_material.counterparty_devid`: that equals the
trader's DevID only under a self-loop shape nothing verifies, and 2c-D §12 records the gap rather
than depending on it.

There is **no `ta_B` field and no receipt field** — the Def 14.2 public Receipt binds `ta_B`, so a
reciprocal field would be circular. There is **no `post_economic_root` field**: the root is derived
by the walk from fields 1–2, and carrying it would invite a verifier to read the carried value
instead of deriving it, which is the failure Req 21.17 tests for. 2c-D ruling D2 applies exactly
that reasoning to `b`.

**Validity, stated as rejections.** Invalid if `acceptance_path` is not exactly 256 elements; if
`acceptance_leaf` does not decode as a canonical `0x0032` schema 1 leaf; or if `trader_genesis` is
all-zero. Verification is 2c-D §7's seven ordered conjuncts, whose step 2 failure is INVALID and
whose step 3 walk failure is INCOMPLETE.

### 5.41 `EconomicBundleAcceptanceState` — class `0x0032`, schema 1

**68 bytes.** A substrate leaf state nested in `0x001E` `EconomicLeafMutation` — the same position
its siblings `0x001F`–`0x0022` occupy, and a fifth arm of the economic state family rather than a
new mechanism beside it. Frozen by
[amendment 2c-D](amendment-2c-d-bundle-acceptance-and-realization.md), which allocates the number
amendment 2c had held in prose.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `bundle` (`b`) | `digest32` | the exact `SettlementBundle` this acceptance realizes |
| 2 | `economic_operation_id` | `digest32` | the authenticated economic operation identity this acceptance belongs to. **Not caller-authoritative** — must equal the enclosing `0x001D` witness's, which is itself recomputed from `(G, DevID, C_dsm+)` |

**No field 3.** Amendment 2c §9.1 requires the authenticated content to commit *"at least `b`"*, and
2c-D ruling D2 forbids adding anything recoverable from `b` — which already commits `X`, the trader
coordinates, the selected route and every `T_v`. In particular the leaf does **not** carry `C_dsm+`:
`economic_operation_id` is the abstraction boundary between DSM transition context and this tree
(2c-D ruling D3), and reaching back through it to restate the raw successor would be the second
representation ruling D2 refuses.

Field 2 follows `0x0022`'s precedent exactly — that leaf carries `consumer_economic_operation_id`
and the verifier requires it to equal the witness's, which is what makes a bare marker attributable.
Here it does the same job **and** fixes the position.

**The key, and why it is not the content.** Amendment 2c §9.1 fixes that the position stays
operation-derived even though the content cannot be:

```text
bundle_acceptance_key(G, DevID, economic_operation_id)
    = H_dom(DSM/economic-bundle-acceptance-key/v1, G ‖ DevID ‖ economic_operation_id)

position_material = (0x0032, [economic_operation_id])
```

`economic_operation_id = H_dom(DSM/economic-operation-id/dsm/v2, G ‖ DevID ‖ C_dsm+)` is the
canonical identity of the exact accepted transition. Its own definition carries the argument: the id
names WHICH authenticated successor performed the operation, while `operation_digest` names WHAT was
performed — and two successors can carry byte-identical operation bytes. So the same operation
against two parents yields two ids and occupies two positions. Keying on `b` is forbidden outright:
it would make the position caller-chooseable, which §9.1 rules a worse defect than a more expensive
Req 21.17 fixture.

**Validity, stated as rejections.** Invalid if `bundle` is all-zero, if `economic_operation_id` is
all-zero, or if its CCB does not re-encode canonically to the bytes presented.

**What the write set may check.** Presence and shape only: `pre: None`, write-once,
`economic_operation_id` equal to the enclosing witness's, the key equal to the derivation above, and
**exactly one** such leaf per economic operation. It must **not** attempt to validate `bundle` — `b` is the first economic
post-state fact not derivable from `Operation::DlvSettle`, so the content-to-operation binding every
other leaf enjoys structurally cannot apply, and an arm that appears to check it is worse than one
that visibly declines to. Amendment 2c §9.1's two-conjunct rule is what replaces it.

### 5.42 `SofiReceipt` — class `0x0034`, schema 1

The Def 14.2 settlement receipt, frozen by
[amendment 2c-F](amendment-2c-f-sofi-receipt-rulings.md). `ρ_B = H_dom(DSM/sofi-receipt/v1,
CCB(SofiReceipt))`; stored under `immutable_addr(DSM/sofi-receipt/v1, CCB)` per §2.11. **137 bytes**
at beta cardinality: 4 envelope + 3×32 + 4 count + one 33-byte entry. Its encoder lives in
`dsm::dlv::sofi_receipt`: it is a projection of `(B, TA_B)`, not reachable from a `VaultStateV2`.

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `bundle` (`b`) | `digest32` | `H_dom(DSM/settlement-bundle, CCB(B))`; `B` must be Market shape |
| 2 | `route_commitment` (`X`) | `digest32` | must equal `B.market_terms.route_set_commitment` |
| 3 | `trader_acceptance` (`a_B`) | `digest32` | `H_dom(DSM/trader-settlement-acceptance/v2, CCB(TA_B))`: the **inner identity**, never the storage address |
| 4 | `transitions` | set of inline `enc(entry)` | `enc(entry) = successor_hash: digest32 ‖ witness_hash: optional digest32` (§2.3), declared inline as §5.2 declares its tuple; one entry per `T_v`; §2.4 order; count `== |B.transitions|` |

`successor_hash = H_dom(DSM/vault-state, CCB(T_v.successor))`, the successor's existing identity.
**`witness_hash` is always absent in schema 1.** Proof material in `B` never makes a receipt
unconstructible, and the receipt adds no witness-validity rule (2c-F ruling on R3).

**Deliberately not fields.** No `vault_id` or parent `c_n`: `V_{n+1}` commits both. No
`economic_operation_id`: it is bound through `a_B` (`TA_B` field 3 → `0x0032` field 2), and 2c-D
D3's three-way equality is the check. No `settlement_receipt_id`: that is the V1 / economic family.
No `storage_set_id` or `q`: those are the authenticated parent's. No signature, so §2.9 applies
vacuously. No timestamp, sequence or node order (Req 14.3).

**Validity, stated as rejections.** A wrong class or schema; a count of 0, or a count
`≠ |B.transitions|`; a `witness_hash` marker `0x01`, or any marker but `0x00`/`0x01`; misordered or
duplicate entries; trailing bytes; any field `≠` its re-derivation from `(B, TA_B)`; `B` not Market
shape. The strict decoder refuses the layout failures, and an exact-length parse of this layout is
the canonical encoding. §2.11 re-hash comes **before** any field is read.

**Not authority.** No composition, admission, realization, fence, certification or
reserve-provenance rule may take a `SofiReceipt`, its address, its presence or its publication
state as input (2c-F R7).

## 6. Blocked objects — what each one needs

These object classes are assigned but cannot be given field tables from Revision 15 as
written. Each entry states the exact missing decision. **None of them should be resolved by
writing an encoder.**

| Class | Object | What the specification says | What is missing |
|---|---|---|---|
| `0x0012` | `TradeDigest` | commits the pair, executed amounts, the parent identity `c_n` of every participating DLV, fees, and `X` | the component types and the ordering of the multi-valued ones. Participating vault identifiers are **not** components: each `c_n` commits its own `vault_id` |

`0x0010` `DlvProofMaterial` left this table at amendment 2c-A: for beta's only declared pricing
family nothing irreducible remains, so §5.22 defines it with **zero fields** rather than inventing
a witness record. `0x000F` `ConsumedDlvTransition` left it too, fully defined at §5.21, and
`0x0011` `TraderAcceptance` left it at amendment 2c-D, fully defined at §5.40. `0x0012` is the last
object in this table.

One class has a partial table in §5, two are fully specified since 2c-B, and one more is blocked:

- `0x0006` `FulfillmentMechanism` is fixed as a preimage —
  `M = H(DSM/fulfillment ‖ c_0 ‖ CCB(B_M))` — so its field order is known and only `0x0008`
  blocks it. Two operands were removed for the same reason, one amendment apart: `Canon(P_M)` by
  the Def 5.2 amendment, and `vault_id` by the state-identity cut. Both are members of `V_0`, and
  `c_0` commits the complete canonical `V_0`, so each was an alias rather than a binding.
- `0x000E` `SettlementBundle` (§5.19) and `0x0033` `MarketTerms` (§5.20) are **fully specified**.
  Amendment 2c-A froze their structure and the identity derivation
  `b = H_dom(DSM/settlement-bundle, CCB)`; amendment 2c-B closed the one remaining blocker by
  fixing `MarketTerms` field 6's nested class as `0x0031` (§5.23). **A conformant market `b` is
  constructible.** The owner-close shape carries no `MarketTerms` and is encodable once the exact
  prepared `close_authorization` bytes are supplied; 2c-B freezes the foreign grammar for producing
  a fresh one. Encoding closure is not verification closure — production acceptance of the market
  shape remains gated on 2c-C3's `ValidDlvSuccessor`, and on 2c-C4's realization fact, whose final
  conjunct only 2c-D can supply — **and 2c-D supplies it** (§5.40, §5.41), leaving the gate on that
  amendment's adopting change.
- `0x0011` `TraderAcceptance` **blocked** on the encoding of `(C_T^+, σ_T^+)`, which is ordinary DSM
  successor material rather than a SoFi object, and therefore needs a decision about whether
  the DSM core encoding is referenced or restated. **Answered by 2c-B**: `0x0031`
  `DsmSuccessorEvidence` (§5.23) references the DSM successor material rather than restating it.
  Ownership of `0x0011` itself is **2c-D's** — 2c-B disclaims it, and 2c-C4 records that `TA_B`
  verification moves with its field table. **2c-D has exercised that ownership**: the field table is
  §5.40 and its verification is 2c-D §7. The nine-field draft in amendment 2c §2 is superseded —
  four coordinates left because they are recoverable from the authenticated `b`, and `bundle` left
  because the authenticated leaf is the single source of truth for it.

## 6a. Amendment 2b — opening object audit

Run before any `Route` field number is frozen, because §2.8 makes them permanent. Four
findings; two are settled by the audit and two need a decision.

> **Superseded by the state-identity cut, and retained as a record.** Everything below reasons from
> `p_v` as the allocation parent binding and from `{EC_v}` as an operand of `X`. Both are deleted:
> `Allocation` `0x0015` schema 2 binds `c_n` and carries no `vault_id`, and `0x0017` schema 2 has no
> encumbrance operand. The *findings* stand as reasoning about the model that existed when they were
> made; the object graph they describe does not. Read §3 and §5 for what is live.

### The object graph Rev 15 already fixed (pre-cut)

`p_v` was **not** an open question at the time of this audit. Def 9.1 defines an allocation as
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

> **Superseded in part by amendment 2c-F R1 (2026-09-11).** `X` stays one 32-byte digest and
> `Canon(X)` stays gone. But the body is `RC*`, the signed RouteCommit's commitment form (§2.10),
> not a CCB `Q`, and `ExtCommit(X)` folds into `X` itself. `0x0017` and `0x000C` are burned. This
> finding's objection to preserving a preimage concerned the four-operand concatenation; R1 does not
> revive it. It ratifies a single-body preimage that shipped, that two parties sign, and that `b`
> carries.

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
| `Route` `0x000D` | the ordered leg sequence | a leg-count bound | 2c-E deleted `max_hops`: `Route` validity now requires the legs to correspond EXACTLY to the signed `RouteCommit` hops, which is a check against a signed fact rather than a bound read out of the intent it bounds |
| `AllocationBundle` `0x0016` | the canonical allocations | `max_fanout` | 2c-E deleted `max_fanout` — it had no wire source and beta emits one allocation per leg. If a later release needs the bound it belongs where the topology is signed, not in the trader's intent |
| `AllocationBundle` `0x0016` | — | the token pair, by default | `p_v` binds the DLV parent, whose state already commits its canonical pair through `P_M`. Carrying it again creates a two-source equality invariant |

The token-pair exclusion is a default, not a certainty: if independent verification turns out
to need the pair as a distinct fact rather than a derived one — a verifier that has the bundle
but not the parent states — then it belongs, and the reason should be written down. Absent
that, it is derived.

### What remains blocked

`TradeDigest` `0x0012` stays last by dependency: §10 binds the pair, executed amounts, the parent
identity `c_n` of every participating DLV, fees and `X`, and those types are determinate only once
findings 1–3 are settled. Note what it no longer binds — participating vault identifiers were
dropped by the state-identity cut, since each `c_n` commits its own.

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
   specified; `ExternalCommitmentBody` `0x0014` is burned. (Amendment 2c-F R1 later burned
   `0x000C` and `0x0017`: the shipped `X` commits the signed RouteCommit, §2.10.) The original
   framing follows, kept for the record:

   **2b (as originally scoped).** `Route` `0x000D`, `RouteSet` `0x000C`,
   `ExternalCommitmentBody` `0x0014`, `TradeDigest` `0x0012`. One dependency cluster:
   `RouteSet` cannot be canonical until `Route` is, the digest binds `X`, and route ranking
   and membership need one byte identity. Existing route SDK and proto structures are evidence
   of current behaviour; only fields implementing already-approved Rev 15 semantics survive.
   An accidental transport field must not become canonical merely because it exists in
   protobuf.

   **2c. Settlement and evidence profile — DECOMPOSED into 2c-A…2c-E; ALL ARE WRITTEN. 2c-A,
   2c-A.1, 2c-B, 2c-C1–C4, 2c-C3.1, 2c-E and 2c-D are frozen; 2c-A.1's and 2c-E's adopting changes
   landed 2026-09-09, and 2c-D's is owed.**
   `DlvProofMaterial` `0x0010`, finishing `ConsumedDlvTransition` `0x000F`, `SettlementBundle`
   `0x000E`, the new `MarketTerms` `0x0033`, and `TraderAcceptance` `0x0011`. Needs the route and
   bundle identity from 2b.
   `TraderAcceptance` derives from Rev 15, not from the current receipt object — the bespoke
   `post_root` receipt is the thing being replaced.

   Review established that 2c cannot be one amendment; the decomposition and its dependency
   argument are in
   [`amendment-2c-settlement-and-evidence-profile.md`](amendment-2c-settlement-and-evidence-profile.md).

   - **2c-A — WRITTEN.** [`amendment-2c-a-bundle-and-transition.md`](amendment-2c-a-bundle-and-transition.md).
     `0x000F` and `0x0010` fully defined (§5.21, §5.22); `0x000E` and the new `MarketTerms`
     `0x0033` **A-stage frozen** (§5.19, §5.20); `b`'s derivation fixed; `0x000B` given its
     satisfaction predicate. **The owner-close shape is encodable once the exact prepared
     `close_authorization` bytes are supplied (2c-B freezes that grammar); a conforming market
     `b` is not, until 2c-B.** *(2c-B has since closed it; the encoder is authorized by 2c-A.1 and
     implemented by its adopting change.)*
   - **2c-B — WRITTEN.** [`amendment-2c-b-accepted-successor-and-recovery.md`](amendment-2c-b-accepted-successor-and-recovery.md).
     Substrate `0x0031` (§5.23) closes `MarketTerms` field 6, and the two foreign byte grammars
     `CloseAuthorizationPreimageV1` and `DlvSettleOperationPreimageV1` are frozen as byte grammars
     rather than as a Rust function. **Complete market `Canon(B)` and a conformant market `b` are
     now constructible.** Declares the beta identity cut its re-basing of the evidence address
     causes.
   - **2c-C — DECOMPOSED into C1–C4.**
     [`amendment-2c-c-verification-closure-decomposition.md`](amendment-2c-c-verification-closure-decomposition.md).
     Economic substrate closure: the namespace record, plus the transitive verification closure,
     including `ValidDlvSuccessor(V_n, V_{n+1}, operation)`. A source audit found ~26 open decisions
     across four dimensions separable in fact, so it ships as **C1** framework + namespace, **C2**
     verification substrate (addressing, SMT, quorum, the authority-resolver contract), **C3**
     `ValidDlvSuccessor`, **C4** the `TA_B` closure walk. (The decomposition also gave "§2 framework extensions required" as a third
     ground; C1 retracts that — §5.2's precedent lets a field table declare an encoding §2 does not
     supply, and no §2 change was needed.)
   - **2c-C1 — WRITTEN.** [`amendment-2c-c1-framework-and-namespace.md`](amendment-2c-c1-framework-and-namespace.md).
     Absorbs `0x001B`–`0x0030` into §3 with field tables §5.24–§5.39, and records the six reserved
     numbers `0x002A`–`0x002F`. Four rulings: the canonical **inner** identity form, `0x0028`
     structurally frozen and beta-refused pending `0x002D`, `0x0029` field 6 admitting no zero, and
     every reserved value appearing in this registry. **Encoding closure for fifteen of the sixteen**
     — `0x0028` is the exception. Verification closure remains C2/C3/C4's.
   - **2c-C2 — WRITTEN.** [`amendment-2c-c2-verification-substrate.md`](amendment-2c-c2-verification-substrate.md).
     Freezes the verification substrate: the economic SMT parameters and bit ordering, the five-step
     leaf chain, the four leaf-key derivations, `K_root`, the four-valued cell observation, and the
     canonical quorum rule. Seven rulings — the authority-resolver contract (never "P0–P6"),
     normative network parameters (§3.2), traversal limits as local policy rather than validity,
     two conformance-vector classes, the signature primitive (§3.1) with a retry rule in place of a
     determinism requirement, `BindingRecordWireV1` as the one named non-CCB grammar (§2.10), and the
     formal debt. **Authenticated retrieval is frozen as a rule (§2.11) and is NOT met by the
     implementation** — three of the walk's four fetches do not discharge it; that is a recorded
     implementation debt, owned by the adopting change. Verification *semantics* remain C3's.
   - **2c-C3 — WRITTEN.** [`amendment-2c-c3-valid-dlv-successor.md`](amendment-2c-c3-valid-dlv-successor.md).
     Freezes `ValidDlvSuccessorCore`: a two-level clause inventory with stable identifiers, the
     complete fifteen-field disposition, derive-and-compare as the successor-state correspondence
     test (`Canon(expected) = Canon(supplied)` is **one conjunct**, not the whole predicate), a typed
     partial `DeriveExpected`, and a two-layer outcome taxonomy over applicable outcomes only.
     **Corrects four Rev 15 errata**, two of which made the predicate unformulable: the burned
     parent-reserves-digest operand, `terminal/retired` having no tuple field, §7.1's `fee_t` being
     non-zero for a family that extracts no fee, and `direction` being carried nowhere. Records that
     `successor_ccb` and `parent_reserves_digest` die with 2c-A's CCB cut, and that until it lands
     the bundle identity `b` is computed over prost bytes in violation of §2.10. **`TokenPolicyValid`
     and the terminal close's exactly-once owner credit are DECLARED AND UNDISCHARGED** — the
     complete predicate is `ValidDlvSuccessor := ValidDlvSuccessorCore ∧ TokenPolicyValid`.
     **Frozen is not the same as implementable:** the successor-correspondence conjunct
     `VDS.COMMON.10.a` is normative and **implementation-blocked on 2c-A's encoder cut**, because no
     authoritative canonical successor bytes exist on the wire today — `successor_ccb` carries the
     route-set commitment on a market bundle and a slot commitment on a close, and both composition
     arms derive the successor locally. C3 also fixes the correspondence test as equality of
     canonical **bytes**, since `decode_vault_state` normalizes rather than refuses and a
     decode/re-encode substitute would launder non-canonical input.
     **Status 2026-09-09 (C3 Phase F):** production `ValidDlvSuccessorCore` is implemented for every
     presently-evaluable conjunct and every fold carries `PartialPendingEncoderCut`; **C3 is CLOSED
     EXCEPT `VDS.COMMON.10.a`**, which stays blocked on 2c-A. Owner-close completion needs 10.a only;
     market completion needs 10.a and the C4 realization fact. The two external conjuncts remain so.
     **Status 2026-09-09 (2c-A.1 adopting change):** `VDS.COMMON.10.a` is IMPLEMENTED —
     `check_correspondence` over the recorded field-2 span, a `CorrespondenceWitness` that exists
     only on byte equality; an owner-close fold is `C3Verdict::Valid`, a market fold is
     `PartialPendingRealization` pending C4's realization fact. **C3 is CLOSED.** The two external
     conjuncts remain so.
   - **2c-C3.1 — WRITTEN.** [`amendment-2c-c3-1-lineage-quarantine.md`](amendment-2c-c3-1-lineage-quarantine.md).
     Freezes the containment Req 6.3 attaches to `SAFETY_VIOLATION` and that 2c-C3 quoted without a
     mechanism: the trigger (duplicate contradictory qualifying binding finality at one parent,
     compared on value and never on round), the scope (the exact parent as root, descendants by
     derivation through the generation bound, never enumerated), durable client-local persistence
     that is not a register value, the five effects as independent observables, **no clearing path
     of any kind**, and the denial-of-service boundary. Adds one reason code, `LINEAGE_QUARANTINED`,
     in the existing class. **Records that the single-read `Conflict` arm is arithmetically
     unreachable at the canonical quorum**, so the trigger is temporal and needs a durable record
     of every qualifying finality. Effects 2–4 are **IMPLEMENTED** by the adopting change, with
     the five-effect integration control and six mutation controls.
   - **2c-A.1 — WRITTEN.** [`amendment-2c-a-1-encoder-cut-rulings.md`](amendment-2c-a-1-encoder-cut-rulings.md).
     Reconciles 2c-A's status text with 2c-B's closure and rules the encoder cut: the encoder
     **surface for both shapes** with class-1 vectors for each (the market vector is the A+B
     closure test), the **owner close cut over now**, and the **market producer fail-closed until
     5c-2 Step 2** re-orders the settle flow so the trader's successor and evidence exist at bind
     time (the ruling was amended the same day on that source finding);
     the owner close's permitted continuation is `c_{n+1}` of the exact field-2 successor and
     `close_slot_commitment` is deleted; an identity-scoped full reprovision; strict decoders
     (field 4 exactly 49,856 bytes, `proof_material` refused present, whole-bundle round trip);
     the transition located by `parent_binding == c_n`; the route-family schema-1 burns recorded;
     namespace enforcement closed; `PartialPendingEncoderCut` replaced by a
     `CorrespondenceWitness` and `PartialPendingRealization`; the protobuf bundle deleted.
     **IMPLEMENTED 2026-09-09 by the adopting change** (record in the amendment): encoder surface
     for both shapes with class-1 vectors, owner-close cutover on `c_{n+1}`, market emission
     fail-closed at every gate's end, `VDS.COMMON.10.a` wired, the protobuf bundle deleted. The
     identity-scoped reprovision (ruling 4) is owed at deployment.
   - **2c-C4 — WRITTEN.** [`amendment-2c-c4-accepted-successor-closure.md`](amendment-2c-c4-accepted-successor-closure.md).
     Closes the verification walk C3 left open: the trusted start (the canonical empty activation
     root or this verifier's own completed validated conclusion — never a network value, and never
     the register winner, since registration is not validation), the numbered economic chain
     `WALK.0..7` at `(G, DevID, p)` ending at a validated economic root, with `R_T^+` **derived** at
     `WALK.6` and required to equal the claim registered at `WALK.1` — which is where Req 21.17's
     forged-root vector dies. Freezes the accepted-successor/economic-root correspondence
     `CORR.1..5`, and the beta refusal of the offline arm with the portable quorum certificate
     Req 6.25 names as its exit condition. Keeps the two coordinate systems apart: everything
     cursor-keyed `(V, c_n, g)` — including 2c-C3.1's quarantine consult, consumed unchanged —
     stays in the composition section. **`IndependentRealization` is DEFINED and NOT CONSTRUCTIBLE**: its constructor takes
     an abstract bundle-acceptance witness that only 2c-D can instantiate, so a market fold stays
     `PartialPendingRealization` and must not be promoted from correspondence alone — and market
     fence release is unreachable until 2c-D, by construction. The market verdict is constructed at
     the ordered third-party composition walk in a core constructor, never pre-filled by the
     trader's own admission path. Restates the two Rev 15 corrections it depends on: `C_T^+` does
     not commit `R_T^+` (2c-B's linked pair) and `L_B` need not bind all four coordinates (§9.1's
     two-conjunct rule). Lands the **fourteenth** Lean module with the 2c-D leaf as an abstract
     Prop parameter; CI module pin 13 → 14. **C4 allocates no class number and changes no encoding.**
   - **2c-E — WRITTEN.** [`amendment-2c-e-trade-intent-exact-output.md`](amendment-2c-e-trade-intent-exact-output.md).
     5c-2 Step 1's fourth document, the one that never landed: amendment 2c had recorded that "the
     selected route satisfies that exact `I`" was left as prose, and it still was. Surfaced by
     checking whether the 5c-2 market producer could be written at all — it could not.
     `MarketTerms` field 1 carries a complete `TradeIntent`, but `RouteCommit` is pinned at version
     2 and carries no `min_out`, `max_fee`, `max_fanout` or `k`; their absence is the deliberate
     removal of v1's slippage floors and pre-signed fallbacks for *"one route, one anchored state,
     one exact output, one signature"*. A fifth member, `max_hops`, was derivable only by inverting
     the authority direction. So the producer could only have invented four of nine members, and
     `I` would have committed to values no verifier could re-derive. Owner ruling: amend the object
     to the shipped model, **spec before code**. `0x000B` **schema 2** is six members reconciled
     against the canonical `RouteCommit` the trader signs — `token_in`, `amount_in`, `token_out`,
     `exact_out`, `fee_bps`, `nonce` — with schema 1 burned and every dropped member re-homed
     (§5.5, and 2c-E §5). States the satisfaction predicate normatively as `SAT.1`–`SAT.6`; `SAT.5`
     carries it, requiring `exact_out` to be checked by re-simulation against the authenticated
     `V_n`, never against the route's own account, or the predicate is a self-attestation. The
     schema bump propagates mechanically under §2.7 to `0x0033` and `0x000E`, moving every market
     bundle's `b` and `addr`. Lands the **fifteenth** Lean module,
     `DSMTradeIntentCorrespondence.lean`, machine-checking `SAT.1`-`SAT.6` with the market policy as
     a parameter; CI module pin 14 → 15. Its load-bearing result is that the FORBIDDEN shape — SAT.5
     compared against the route's own claim rather than the authenticated `V_n` — accepts a forgery
     the real predicate refuses, so the two are provably different predicates.
     **2c-E allocates no class number.** Its adopting change — the encoder
     and strict decoder cut to schema 2 with schema-1 bytes refused as burned, the formal predicate,
     the producer, the class-1 market vector regenerated exactly once from it, and three mutation
     controls — **LANDED 2026-09-09**: `(0x000B, 1)`, `(0x0033, 1)` and `(0x000E, 1)` are in
     `ccb::schema::BURNED`, the fifteenth Lean module is pinned in CI, and the market operands are
     the genuine producer's.
   - **2c-D — WRITTEN.** [`amendment-2c-d-bundle-acceptance-and-realization.md`](amendment-2c-d-bundle-acceptance-and-realization.md).
     The fourth and final amendment of the series, and the one every other member stopped at.
     Defines `0x0032` `EconomicBundleAcceptanceState` (§5.41) — a substrate leaf state nested in
     `0x001E`, carrying exactly one field, `bundle`. Its CONTENT commits `b`; its POSITION stays
     operation-derived per amendment 2c §9.1, keyed on `economic_operation_id`, the canonical
     identity of the exact accepted transition — `operation_digest` would name the operation but not
     the transition and would let one operation against two parents collide (ruling D3). Re-derives `TraderAcceptance` `0x0011` (§5.40) from
     nine fields to four; a **first freezing, not an amendment to frozen bytes**, so nothing is
     burned. Two owner rulings: `trader_genesis` SURVIVES as a carried authenticated witness because
     it is not recoverable from `b` — it enters only through `sigma_dsm`'s signing digest, so a
     verifier can check but not recover it — while field 1 `bundle` LEAVES, because once the leaf is
     authenticated it is the single source of truth for `b` and a second copy is the same defect the
     registry already refuses for `post_economic_root`. The invariant both share: *one authoritative
     source per coordinate wherever derivation permits it.* `trader_devid` is dropped as
     `operation_bytes.settler_devid` — NOT as `recovery_material.counterparty_devid`, which is only
     the trader's under a self-loop shape nothing verifies — and that route forces a new conjunct:
     the DevID used to reconstruct the signing digest must equal `settler_devid`, since G1–G4 never
     relate the trader's two appearances. Gives `BundleAcceptanceWitness` its only constructor, so
     2c-C4's boundary holds by construction. **2c-D allocates `0x0032` and moves no schema.** Its
     adopting change — the registry rows (this document), the domain tag, the fifth `EconomicState`
     arm, the write-set arm, the verifier, the witness constructor, class-1 vectors, Req 21.15's
     realize half and Req 21.16, a Lean module, and six mutation controls — is NOT started.

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
| **Design normatively** | the specification only names a concept | **evidence, not authority** |

Most of §6 falls in the second tier.

**There is no "absorb as shipped" tier.** An earlier revision had one, justified by the deployed
`storage_set_id`: compatibility was said to be protocol-significant because changing the layout
would break live commitments. The state-identity cut deletes the anchors that carried those
commitments and reprovisions, so nothing live depends on any shipped layout. Under a no-legacy rule
that tier has no members and no way to acquire one — a shipped encoding is evidence of what an
implementation does, never authority over what the protocol is.

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

The one still-blocked class — `0x0012` — belongs to the remaining settlement sub-amendments and
does not gate Anchor V2. (`0x0011` was the second until 2c-D defined it at §5.40; `0x000D` and
`0x0010` are now defined; `0x0014` is burned, and 2c-F burned `0x000C` and `0x0017`.)
