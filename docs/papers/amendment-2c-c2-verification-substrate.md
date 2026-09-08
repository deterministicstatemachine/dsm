# Amendment 2c-C2 — the verification substrate

Status: **SUBSTRATE FROZEN: canonical identity and authenticated retrieval, plus the reusable
algorithms later verification consumes. `ValidDlvSuccessor` IS NOT DECIDED HERE — that is 2c-C3.**
2026-09-08.

Normative and encoder-free. Second of the four sub-amendments fixed by
[`amendment-2c-c-verification-closure-decomposition.md`](amendment-2c-c-verification-closure-decomposition.md),
building on [`amendment-2c-c1-framework-and-namespace.md`](amendment-2c-c1-framework-and-namespace.md).

## The three layers, and why the boundary is the whole design

C2 exists because three questions are easy to blur and expensive to conflate:

```text
(1) canonical identity        what exact bytes / digest NAME a thing
(2) authenticated retrieval   how a verifier OBTAINS it and PROVES it is the one named
(3) verification semantics    what predicate applies once it HAS it
```

**C2 owns (1) and (2), plus the reusable algorithms (3) consumes. C2 does not own (3).** What makes
a DLV continuation valid is 2c-C3's `ValidDlvSuccessor`; how those results compose into an accepted
successor proof is 2c-C4's. Everywhere this amendment touches something that looks like a semantic
judgement, it names the owner and stops.

The reason the seam is drawn here rather than anywhere else: layers (1) and (2) have exactly one
correct answer that two implementations must agree on byte for byte, and no policy content. Layer
(3) is where policy lives. Freezing them together would put a judgement call inside a specification
of bytes, which is how a substrate stops being reusable.

## What C2 inherits from C1 and does not re-decide

2c-C1 ruling A is load-bearing throughout: every provenance-index entry and every `*_addr` field of
the economic classes carries the canonical **inner** content identity `H_dom(N, P)`. The outer
storage-object address `H_dom(DSM/storage-object, N ‖ H_dom(N, P))` is used only when talking to the
immutable storage layer and is never the canonical provenance identifier. C2 does not reopen it; C2
says what a verifier does with it.

---

# Ruling A — the authority-resolver contract is frozen; the predicates are not C2's

SoFi **consumes** authenticated identity authority. It does not **redefine** DSM identity
authority. That architectural property is what this ruling protects.

## The finding that forced it

The decomposition routed *"P0–P6 as normative predicates"* to C2 on the assumption that those
predicates were already normative somewhere. They are not.

**Rev 15 contains zero occurrences of `P0`.** The specification is 2,652 lines; the search returns
nothing. `P0`–`P6` is a **code-local numbering convention** in
`core/identity/authority_resolver.rs`, and it describes the general owner-authority resolver — not
anything economic. The economic layer contributes no predicates of its own: it calls *"the SAME
resolver every other authority check uses"* and takes back two facts.

Elevating an implementation's internal decomposition into SoFi protocol law because it happens to
expose seven internal checks would be scope creep in the most literal sense — the numbering is a
property of one Rust module, not of the protocol.

## What C2 freezes

```text
C2 FREEZES:
    the canonical inputs supplied to the authority resolver
    the required stage / order of the authority walk
    the applicable descent / depth rule
    the authenticated facts returned to the economic layer
        proven_ak
        network_id
    failure semantics: unresolved or invalid authority => refusal

C2 DOES NOT FREEZE:
    the names P0 ... P6
    the seven internal predicates as economic-layer rules
    the implementation-local decomposition of the authority resolver
```

> `P0`–`P6` is current implementation terminology, **not a Rev 15 normative interface**. Any
> amendment that standardizes those seven predicates belongs to the general DSM identity/authority
> layer, not to the SoFi economic verification amendment.

## The contract, stated normatively

**Inputs.** The expected `G`, the expected `DevID`, the `authority_position` the admission manifest
commits, and the presented authority-evidence bytes named by `authority_evidence_addr`.

**Returned facts, and only these two.**

```text
proven_ak    the authority key the resolver proved for that identity at that position
network_id   the committed network, recovered by RECOMPUTATION from the genesis
             parameters whose recomputation IS G -- never accepted from a claimant
```

The economic layer may depend on these two and on nothing else the resolver computes internally.

**A foreign verifier's only a priori input is `G`.** Everything else is presented, and nothing
presented is trusted before the stage that authenticates it.

**Stage order is normative.** A verifier that recomputes the device identity before authenticating
the root has proven only that a presented triple is internally consistent — anyone can generate a
keypair and a 32-byte value whose hash matches a leaf they also chose. A verifier that checks
membership against an unauthenticated root has proven membership in a tree the attacker supplied.
The order is part of the contract precisely because both of those mistakes produce a confident
"valid".

**Descent, never frontier.** The resolver proves that a key was the authority for an identity at a
**bound position**. It does not prove currency: no presented chain can carry *"no newer position
exists."* C2 records this as a hard limit of the substrate, and **it bounds what 2c-C4 may
conclude** — a valid descent proof can never be promoted into a statement about the tip.

**Failure is refusal.** Unresolved or invalid authority is a refusal, never a downgrade to a weaker
acceptance. The resolver's own taxonomy separates **absent** (liveness — the material may simply not
have been published), **incomplete** (a chain exists but does not reach what was asked) and
**invalid** (a signature fails, a link breaks, a fork is observed). The economic wrapper collapses
absent and incomplete into one incomplete arm. That collapse is safe because both are liveness, and
C2 records it rather than leaving a reader to discover that the two taxonomies differ.

---

# The beta network parameters — published, because a verifier cannot derive them

## Ruling B — the root-register profile is a normative per-network parameter

> For each supported network identifier, the economic root-register profile is a **normative
> protocol parameter**. A verifier derives `network_id` from authenticated genesis and selects the
> exact profile specified for that `network_id`. Local configuration, build-time defaults,
> environment variables, and independently compiled tables are **not authoritative**.

The problem this closes is precise. The profile is resolved from a compile-time table keyed by a
network id that the claim's own authenticated genesis commits — so it is not local mutable config,
and a claimant cannot steer it. But it is also **not committed anywhere in the object graph**, and
the pinned incarnation values are, in the source's own words, *"not derivable from anything in this
source tree, which is the point."* Two conforming verifiers built from different tables would reach
different verdicts on the same authenticated lineage, and nothing would detect it.

The resolution keeps the values as **network parameters rather than fields inside every economic
object**. Because `network_id` is itself authenticated and the mapping from `network_id` to profile
is normative and immutable, the three member identities need not be redundantly committed in every
state.

```text
authenticated genesis  ->  network_id  ->  normative parameter table  ->  exact profile
```

## The `dsm-testnet` profile

`network_id = "dsm-testnet"` (ASCII, 11 bytes).

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
`H_dom(DSM/storage-set, CCB(StorageSet))` over the `0x0002` **schema 3** object built from exactly
those three `(member_id, register_incarnation_id)` pairs, in that order. The value above was
computed from the frozen definition and is reproduced here so a foreign verifier can check its own
derivation without holding this repository's build.

**Membership and set id come from one source.** Both derive from the same pinned pairs, so the two
cannot drift apart. This is why `0x0002` went to schema 3: a set of bare member ids says only
*which nodes* a vault trusts, and a member that rebuilt its register still satisfied it. Pairing
each member with its incarnation removes exactly that ambiguity — **a rebuilt member is a different
entry**, so a claim written under the old incarnation no longer names the set the network resolves
to.

**A catalog resolves; it never chooses.** A catalog may say *where* a member is reached and *which*
incarnation it claims. The pinned `storage_set_id` decides whether that is the register the network
actually commits to: a candidate whose membership is not this network's, or whose re-derived set id
is not the pinned one, is refused. Every resolution failure is fail-closed — there is no default
register and no fallback set, because a default register is one an attacker can steer traffic into.

A network whose identifier has no entry in this table is **unknown, not permissive**: verification
refuses.

---

# Ruling C — traversal limits are local resource policy, never validity

> Walk-step budgets, cross-identity depth caps, and equivalent traversal limits are **local
> denial-of-service and resource controls. They are not consensus, validity, or protocol
> parameters.** Exhaustion produces an **incomplete** verification result. A caller MUST fail closed
> for acceptance, and MUST NOT convert resource exhaustion into evidence that the underlying claim
> is invalid.

## Why the distinction is load-bearing

The two limits answer *"how much work will this verifier perform before stopping?"* They do not
answer *"is this lineage cryptographically invalid?"* Those are different questions, and collapsing
them makes local CPU and stack policy part of protocol truth.

```text
Verifier A   reaches the proof                    -> VALID
Verifier B   exhausts its local budget first      -> INDETERMINATE

never:
Verifier B   exhausts its local budget            -> INVALID
```

Under the wrong reading, two verifiers with different limits would disagree about whether the
**same** claim is valid — a divergence in the protocol's verdict produced entirely by a local
resource setting. Under this ruling they disagree only about whether they could *finish*, which is a
statement about the verifier and not about the claim.

## The second distinction, frozen explicitly

```text
fail closed for ACTION       do not accept / advance / realize
DOES NOT MEAN
classify the evidence as     INVALID
```

Both currently lead to "don't proceed", and that shared consequence is exactly what would tempt a
future implementation to collapse `Incomplete` into `Invalid`. C2 forbids the collapse. An
incomplete result is a statement that the verifier stopped looking; an invalid result is a statement
about the evidence, and only the second is a finding about the claimant.

## What is not a budget

```text
provenance cycle       INVALID -- validation edges must point strictly backward;
                       a cycle is a property of the evidence graph, not of the verifier
authority failure      per the resolver contract in ruling A
```

A detected cycle is refusable on its own evidence. Running out of traversal budget merely means the
verifier stopped.

## On the specific numbers

The current implementation carries a total step budget and a cross-identity re-entry depth cap, and
the shipped values are **implementation defaults and documented operational settings — not part of
the foreign-verification contract.** C2 deliberately does not publish them as normative or even as
recommended protocol values: a published number invites an implementer to treat agreement on it as
conformance, which is the confusion this ruling exists to prevent.

The implementation's own reasoning already classifies them correctly. The depth cap exists to bound
the Rust stack, since each re-entry is one frame — an implementation resource concern in its own
words — and the exhaustion arms return incomplete with the reason *"walk budget, not a forgery."*
This ruling makes that behaviour normative rather than incidental.

---

# Ruling D — two classes of vector, and only one of them is evidence

> A conforming implementation **MUST reproduce every published vector byte for byte.** Failure of a
> vector means implementation nonconformance. **The vector does not override the normative
> algorithm** if a transcription mistake in the vector itself is later discovered.

```text
NORMATIVE        the algorithms, domains and encodings this amendment defines
CONFORMANCE      fixed inputs and their expected outputs, DERIVED from those rules
```

The vectors are executable checks that an implementation has read the definition correctly. They are
never an alternative definition of the protocol.

## The two classes, and why the distinction is not editorial

```text
1. NORMATIVE CONFORMANCE VECTORS
   generated from an INDEPENDENTLY WRITTEN encoder
   MUST NOT call production CCB encoders, decoders, canonicalization helpers
       or digest-construction helpers
   derived solely from the registry / amendment grammar
   THIS is the primary cross-implementation evidence

2. PRODUCTION REGRESSION VECTORS
   generated from the shipping implementation
   pin known outputs against accidental drift
   useful in CI
   NOT, by themselves, evidence that the specification is independently implementable
```

> **A conformance vector is independent only if its expected bytes are produced without invoking the
> production encoder, decoder, canonicalization helper, or digest-construction helper whose
> behaviour the vector is intended to test.**

Without that rule a vector can prove only `implementation == itself`. The repo already knows this:
`dsm/tests/ccb_conformance.rs` writes an encoder **from the registry text and refuses production
helpers**, on the stated ground that *if the two agreed because they shared code, agreement would
prove nothing*. It covers `0x0001`–`0x000A` only.

**C2 obligates extending that independent-encoder coverage to the economic classes `0x001B`–`0x0030`
that C1 absorbed, and to the economic SMT constructions frozen here.** That obligation is the
conformance surface for this amendment; the vectors below are the second class and do not discharge
it.

**Encoding.** Digests and identifiers are **Base32 Crockford**, per the repo's hard invariant. Where
a vector needs exact canonical *bytes* rather than a digest, they are given in a non-hex
machine-readable form — byte arrays or an attached binary fixture — never hex. The closest existing
precedent, `dsm/tests/whitepaper_kat.rs`, pins in hex and is **not** the pattern to follow; C2
records that as a defect in that file rather than a licence.

## The vectors below are class 2

Everything in the remainder of this ruling was produced by running the shipping functions. It is
**production regression evidence**: it catches a refactor that changes the bytes, and it does not
establish that this document is sufficient to reimplement from. The class-1 obligation above is
where that proof lives.

## Depth and default-node vectors

`empty_economic_root()` takes **no inputs at all** — a pure protocol constant that any
implementation can check before writing a single fixture.

```text
ABSENT_LEAF            0000000000000000000000000000000000000000000000000000
default_node(0)        0000000000000000000000000000000000000000000000000000
default_node(1)        32RWB0CRHH1ZJHTERV6MFATN68E5D878ZQPRMA6WSPK204Q7AQH0
default_node(2)        5ADN03HMZ68YY0789SPGSD8CBG1ZXA2M630M3BZDB55GTPG8MWBG
default_node(255)      4WF95FY60CBSTA9ZBPYWSJZC5P8KTC2Q7VYSN9SQQD6M21E8X4R0
default_node(256)      J94S2AFC6RYWZKHE0TN4RS1PHQFD4GYWARAR62CMY0JMTYMP13EG
empty_economic_root()  J94S2AFC6RYWZKHE0TN4RS1PHQFD4GYWARAR62CMY0JMTYMP13EG
```

`default_node(255)` is the end-of-depth control: an implementation that builds its defaults table
off by one level fails here while still passing levels 0–2.

Two self-consistency identities hold and were checked in the same run:
`econ_node(ABSENT_LEAF, ABSENT_LEAF) == default_node(1)` and `ABSENT_LEAF == default_node(0)`.

## Leaf-key vectors

At `G = 0x11×32`, `DevID = 0x22×32`, `policy_commit = 0x33×32`, `vault_id = 0x44×32`,
`receipt_id = 0x55×32`, `source_id = 0x66×32`:

```text
balance_key             W7X0KYYTX2CDZ3WVZ6YPF6ZNM08YJWEBNM2S3XGXKNT4Q2YX3CC0
vault_reserve_key       PPQ96JX6AERXMTKXBBY463TZ90RMSQ9JRC7A99S91X80HSM19P40
settlement_receipt_key  G5AKWT8AJEVH5SX231R83WYDNW7SDCEV8PZ3TZHZR7E9AP5RH780
consumed_source_key     VXBS5SFBFRVQBKVQ9KFH5RVQM1D0Y4A08XHF9D3MFF9FCC0T6DA0
```

## The complete leaf-to-root vector

This is the important one: it exercises the whole composition rather than testing helpers
independently.

`EconomicBalanceState { policy_commit = 0x33×32, amount = 1000 }`

```text
CCB length      44 bytes        <- exactly what 2c-C1 §5.28 froze
leaf_key        W7X0KYYTX2CDZ3WVZ6YPF6ZNM08YJWEBNM2S3XGXKNT4Q2YX3CC0
leaf_value      MG24V90E0Z7PK9X66FR6K8SGPZKJX15SZZ97WZZ74Y76RXHCNC5G
econ_leaf(k,v)  CKMYFFK5PVHFFWV96JK3R17VSQJ0PHGTYA21DMZVQMBZ01V6A6N0
one-leaf root   145Q75CF6T0E7PSS2MZY5RMCQNZ0ADF4SHD8XAJ9YRACKPXDR580
```

The `leaf_key` equalling `balance_key` above is the dispatch check: the leaf state's own key
derivation and the standalone function are one function reached two ways.

## The mixed-path vector and its anti-transposition controls

A key whose 256-bit path is deliberately non-trivial, so that reversing bit order, byte order, or
traversal direction **must** produce a different root. `key[i] = (37·i + 0xA5) mod 256`,
`value = 0x5A×32`, siblings `siblings[i] = default_node(i)`.

```text
key             MQ5EY51SBT1THKFJ2WY631NBT3THMFV4H6QD7Y0X89KRSCEPZCG0
econ_leaf(k,v)  Q7QJ11AKS5PGDHSQCG5F1SQ8XCSBN3RBD6HRZMHEPTD5829CB79G
root            80VE8B0FSJ5ECD4EWWWTZZFTK8BCSZE2ZAQTXPR6WNGBG2803ECG
```

Three controls, each of which **must** differ from that root. All three were executed and all three
differ:

```text
siblings array reversed        J6G2G2M5S2XS0Y2XRGVEPKQHX5VKRNTN4PSP8536HT6YZFA9HYX0
key bytes reversed             GZT4RH668T7T7KFZJ04M0YXN8DN2ZYD0RCP7QG5N6V6YM5VXSCJ0
econ_node arguments swapped    FVY25V33CBR2YQ6GF7F9QM276SAC21W93DWQCSYN4C8182P5GZE0
```

An implementation that reproduces the root but also reproduces any control has not implemented the
ordering — it has implemented a symmetry that the real tree does not have. The controls are
published for exactly that reason: a single expected root can be hit by a wrong implementation that
is wrong twice.

---

# Ruling E — the signature primitive is part of the frozen substrate

C2 claims to freeze the algorithms foreign verification consumes. The verification algorithm itself
was missing from that claim, and it is the single most likely point at which foreign verification
actually fails.

## The finding

The shipped implementation uses **BLAKE3 for all hash, PRF and thash operations** instead of
SHA2/SHAKE. Its own header says so, and says it *"has NOT been formally audited."* The structure
(FORS + WOTS+ + Hypertree) and the parameter sizes match the standardized sets — so the public key
is 64 bytes and the signature 49,856 bytes, which are **exactly** FIPS-205 SLH-DSA-256f's sizes.

Registry §3.1 declares the member by **name and those two sizes, and nothing else**:

```text
| 0x0001 | SPHINCS_PLUS_SPX256F | 64 bytes (2n, n = 32) | 49,856 bytes |
```

A foreign verifier implemented from §3.1 links a standards-conformant SLH-DSA library, gets
**byte-identical key and signature lengths**, and every DSM signature fails verification with no
size mismatch to diagnose it. §3.1's own closing sentence — *"the algorithm and the key bytes stand
or fall together"* — is **false as written**: matching key and signature widths do not identify an
algorithm.

## The ruling — two findings, deliberately split

**1. Freeze the actual construction, and correct §3.1.**

> `signature_alg = 0x0001` identifies the exact DSM construction a foreign verifier must implement:
> the SPX256f structure and parameters, with **DSM's BLAKE3-based hash / PRF / thash construction**.
> It is **not** FIPS-205 SLH-DSA-256f, and the coincidence of public-key and signature lengths with
> SLH-DSA-256f does not make it so. The construction carries an unambiguous normative designation —
> a DSM BLAKE3-SPHINCS+-SPX256F name — so that no implementer can reasonably select a standards-only
> SLH-DSA library and silently fail every signature.

The numeric id **remains `0x0001`**. This is a correction and closure of an existing, already-shipped
id, not a new wire algorithm; inventing a second algorithm number merely to retire a misleading
label would burn a number for a documentation defect. §3.1's "stand or fall together" sentence is
corrected in the same edit.

**2. Signing determinism is NOT made normative.**

The shipped signer is deterministic — `R = BLAKE3_keyed(sk_prf, m)`, with `OsRng` appearing only in
keygen — and the write-once register currently depends on that: under a hedged signer the same body
would yield a different envelope, a different envelope digest, and an honest retry after a lost
response would read **Contested against itself**.

That is a **retry / object-identity defect, and it is fixed at that layer** — not by requiring every
future signer to be deterministic. FIPS-205's own default is the hedged variant; freezing
determinism would permanently exclude a hedged signer to paper over a retry rule.

> **Normative retry rule.** Once an exact signed candidate is prepared, its exact signature bytes
> and its exact canonical object bytes are **frozen** and MUST be reused for retries, recovery and
> re-publication. **A retry MUST NOT regenerate a signature and assume byte equality.**

Foreign verification requires the exact **verification** algorithm. It does not require proof that
another conforming signer would reproduce identical signature bytes. The current deterministic
signer is recorded as an implementation property and a useful test vector — never as protocol
validity.

```text
MUST be deterministic
    canonical encodings
    hashes from fixed inputs
    the verification result
    state-transition predicates

MUST NOT be relied upon as deterministic
    signature generation

Retry stability means
    reuse the exact prepared signature
    NOT  generate the same signature again
```

---

# Ruling F — the binding record is a frozen storage-wire grammar, not a protobuf exception

`dsm/src/storage/binding_record.rs` computes three domain-separated identities —
`record_digest_of_bytes`, `record_set_keys`, `record_set_digest` — over
`self.to_proto().encode_to_vec()`. A search of the registry for *"binding record"* returns **zero
hits**: a hashed, node-inspected, normative structure sits entirely outside the namespace C1 just
made canonical.

The obvious fix is wrong. The module states its reason plainly: *"the node hashes what it STORES
(the canonical protobuf bytes), never a decoded view of it."* Cutting prost here the way the
economic identities are cut would push CCB parsing **into the storage node**, across the Class N
boundary:

```text
Class N
    stores opaque generic bytes
    hashes exactly what it stores
    does not interpret application objects
    does not parse CCB
```

## The ruling

The distinction that matters: the economic cases leaked a **transport serialization into
application-semantic identity**. Here, *"hash what I physically store without interpreting it"* is
the storage primitive's design. So the boundary is preserved — but **no generic protobuf exception
is created**, because that would become precedent for arbitrary protobuf-derived identities
elsewhere.

> C2 freezes the binding-register wire representation as a named, exact **storage-layer canonical
> byte grammar**: `BindingRecordWireV1`. The current protobuf encoding is byte-identical to that
> grammar and is its **present implementation** — protobuf itself is not the normative authority.

Normative properties:

```text
Class N hashes the exact BindingRecordWireV1 bytes it stores.
Class N MUST NOT decode CCB or application objects to compute these identities.

record_digest_of_bytes, record_set_keys and record_set_digest are defined over
the exact frozen BindingRecordWireV1 bytes.

BindingRecordWireV1 is NOT a CCB object. It has no CCB class and no schema envelope.

This is a NARROWLY NAMED storage-substrate exception to the rule that protocol and
application identities derive from CCB. It is not permission for arbitrary
protobuf-derived identities.

Future changes to those bytes require an explicit storage-wire version or amendment.
A protobuf library refactor MUST NOT silently change them.
```

The shipping `to_proto().encode_to_vec()` output is **evidence that the current implementation
matches `BindingRecordWireV1`**, never the protocol definition. Leaving the normative definition as
`prost::encode_to_vec()` would leave a library implementation as protocol authority, which is the
failure §2.10 exists to prevent — the same reasoning 2c-B applied when it froze two foreign byte
grammars rather than naming a Rust function.

The resulting split:

```text
economic / application objects        ->  CCB canonical identity
generic binding-register storage      ->  frozen opaque storage-wire identity
                                          hash exact stored bytes
                                          no application parsing by Class N
```

---

# Ruling G — the formal debt, named precisely rather than deferred vaguely

`lean4/` and `tla/` contain **zero** references to the economic tree — no `econ_leaf`,
`economic_root`, `R_econ`, `EconomicSmt` or `K_root`. Every SMT the models cover is the relationship
SMT or the device SMT. C2 freezes a **third** tree with a distinct leaf-key family, a distinct node
domain, a distinct root construction, and an all-zero `ABSENT_LEAF` that is the deliberate opposite
of the modelled one.

C2 is a specification amendment and does not block on model work. It also does not leave *"formal
models pending"* as a vague note.

> **2c-C2 does not claim formal-model closure.** No existing Lean or TLA model covers the economic
> SMT. Before the C2 economic-SMT construction is adopted in production, formal coverage must
> establish at least the following **non-aliasing obligations**, under DSM's symbolic hash and
> domain-separation abstraction:
>
> 1. each economic leaf-key derivation is injective over its declared input domain;
> 2. the leaf-key domains are pairwise disjoint across the four economic leaf classes;
> 3. `K_root` cannot alias any economic leaf-key domain;
> 4. the economic SMT node and root domains cannot alias the leaf domains;
> 5. `ABSENT_LEAF` cannot be confused with a valid populated leaf commitment;
> 6. the resulting economic SMT preserves the non-interference property expected from independently
>    keyed state domains.

**These are stated under the symbolic abstraction, not as theorems about BLAKE3.** Claiming literal
injectivity of a fixed-width hash over an unrestricted domain would be claiming something no one can
prove; real implementation safety reduces to the ordinary collision-resistance assumption. The
obligations are about **domain separation and non-aliasing**, which is what the construction
actually relies on and what a model can actually discharge.

**CORRECTION.** An earlier revision of this ruling said `DSMNonInterference.lean` *"proves leaf-key
injectivity for the relationship SMT"*. **It does not.** `relKey : Nat → Nat → Nat × Nat` is a
min/max sort of two naturals, and `relKey_injective` proves that sorting an unordered pair is
injective. That file contains **no hash, no SMT, no domain separation, and zero axioms** — the
BLAKE3 leaf-key derivation it nominally corresponds to is not modelled there at all. The real
precedent for a hash-derived key is `DSMCertChain.lean`. An implementer who read the original
sentence and assumed the relationship tree was covered would have been misled about both trees.

Two further corrections to the obligations as written above, both found while discharging them:

- **Obligation 4 presupposes a root domain that does not exist.** `empty_economic_root()` is
  `default_node(256)` and every non-empty root is an `econ_node` output, so **node and root are one
  domain**. The Lean module proves that (`root_lives_in_the_node_domain`) rather than asserting it;
  a model that tried to separate them would be proving something false. The real content is node vs
  leaf vs leaf-state.
- **The leaf-state domain `DSM/economic-leaf-state/v1` is missing from the list** but is step 2 of
  the frozen five-step chain, and belongs in the disjointness set. It is included in the discharge.

And one scoping caveat: **obligation 1's input domain is not closed** for the settlement-receipt and
consumed-source keys, whose `receipt_id` and `source_id` are themselves domain hashes. Injectivity
is discharged relative to the **declared 32-byte inputs**; the nested derivations are a recorded
dependency, not part of that chain.

```text
2c-C2                    freezes the economic SMT definition
                         identifies the exact formal obligations

DISCHARGED               lean4/DSMEconomicSmtSeparation.lean  (obligations 1-7)
                         tla/DSM_EconRegisterObservation.tla  (the concurrent
                                                               register half)
```

**The claim boundary, stated so "formal verification" stays precise:**

```text
Formal coverage establishes the stated properties of the normative
economic-SMT and economic-register MODELS.

It does NOT constitute a machine-checked refinement proof that the
shipping Rust implementation implements those models.

Implementation correspondence is supported separately by conformance
vectors, source-level invariants, tests, and deliberate falsification
controls.
```

**Nor is the Lean module "axiom-free" without qualification.** The quorum results are. The economic
hash and non-aliasing results rest on the symbolic abstraction declared in that module's header, and
its adequacy bridge additionally rests on a **local** collision hypothesis — and, for obligation 5's
byte-level form only, on a **local** zero-sentinel hypothesis. Neither is a global claim about
BLAKE3: a universal "distinct preimages give distinct 256-bit outputs" would be *false* by
pigeonhole, and "no populated economic preimage produces `0^256`" is not implied by preimage
resistance, which speaks only to the infeasibility of finding one.

---

# Authenticated retrieval — the obligation, and where it is not met

## The rule

> **Every fetch of an addressed object is followed by recomputing that object's canonical identity
> over the bytes actually returned and comparing it to the address that was asked for, BEFORE any
> field of the object is read.** A mismatch is a refusal, never a repair. A decode that succeeds is
> not a substitute: decoding proves the bytes are well-formed, not that they are the bytes that
> address names.

This promotes Rev 15 Req 15.3's consumer obligation into a substrate rule that every later
verification step inherits, and it is the whole of what "authenticated retrieval" means in this
amendment. It is deliberately stated as an obligation of the **consumer**, not of the fetcher: a
fetcher is an untrusted I/O boundary, and a rule that a fetcher must return honest bytes is not a
rule a verifier can check.

Per 2c-C1 ruling A the recomputed value is the **inner** identity `H_dom(N, P)`. The outer
storage-object address is what was used to reach the storage layer; it is never what the comparison
is against, because it is not the object's identity.

## The current walk meets it once out of four times

The validated-root walk fetches four addressed objects. Read from source on a clean tree:

| # | Object | Fetched at | Re-hash and compare |
|---|---|---|---|
| 1 | admission manifest `0x001C` | `peer_lineage.rs:348-352` | **PRESENT** — `manifest.addr()` compared at `:355-360` |
| 2 | authority evidence | `peer_lineage.rs:363-366` | **ABSENT** |
| 3 | transition witness `0x001D` | `peer_lineage.rs:406-411` | **ABSENT** |
| 4 | successor evidence `0x0031` | `peer_lineage.rs:421-422` | **ABSENT** |

Neither verify function recovers the check internally. `verify_authority_evidence`
(`authority_evidence.rs:99+`) and `verify_dsm_successor_evidence` (`successor_evidence.rs:151+`)
both decode and proceed; neither calls its module's own `*_addr` function. Those functions exist —
`authority_evidence_addr` at `authority_evidence.rs:69-71`, `successor_evidence_addr` at
`successor_evidence.rs:88-90` — and are simply not used on the consume path.

**The module's own documentation asserts the opposite.** `peer_lineage.rs:61-62` reads:

> *"immutable objects whose bytes re-hash to their address. The walker re-checks the address anyway
> — a fetcher cannot substitute bytes."*

That sentence is true of the manifest and false of the other three. It is worse than a silent gap:
a reader auditing this path is told the check is there. The comment must be corrected in the same
change that adds the checks, or it will keep certifying an absence.

## Why the strict decoders do not close it

Both evidence decoders perform prost decode plus re-encode equality — the settlement-wire
discipline, so that two byte strings can never decode to one object. That makes the address
**exact given a byte string**; it says nothing about whether the byte string is the one the address
names. Canonicality and authenticity are different properties, and only the second is at issue
here.

## What a substitution buys an attacker

The three unchecked objects are not decorative. Authority evidence carries the proven AK and the
committed network id, and the walk immediately uses both to resolve the register profile and to
decide whether the claim's signing key is the proven one. The witness carries the pre- and
post-roots. The successor evidence carries the accepted substrate. A fetcher that returns
well-formed bytes for a *different* object at any of those three addresses is not detected by
anything downstream — the objects are consistent in themselves, merely not the ones the manifest
named.

## Three findings that make the gap worse than a missing line

**There is no reusable fetch-recompute-compare helper in the core crate.** Every consumer open-codes
the comparison against a per-class `*_addr()` helper. The two real helpers live in `dsm_sdk`, where
the core walker cannot reach them. A rule discharged by open-coding at eleven sites is a rule that
will be missed at the twelfth — and it was, three times, in one function. **C2 requires the
obligation to be discharged by a single named construct rather than by convention**, so that a
consumer cannot obtain a usable object without the comparison having happened. The codebase already
uses exactly this idiom on this walk for the same class of risk: `ValidatedEconomicRoot` has a
private field and no public conversion from its unvalidated counterpart.

**`validate_peer_lineage` has no test anywhere in the workspace.** The three missing re-hashes have
no mutation control, and none of the walker's conjuncts is proven load-bearing. Under the repo's
standing rule — remove a gate, watch a *named* test go red by actually performing the forbidden
action, restore it — none of these conjuncts has ever been shown to be a gate at all.

**One conjunct downstream is tautological on this path.** `advance_validated` compares the manifest's
`evidence_addr` against the accepted substrate's `evidence_addr`, but the walker constructs the
accepted substrate *from that same manifest field*. The comparison cannot fail, so it establishes
nothing while reading as though it does. Relatedly, `transition_witness_addr` has exactly one
consumer in the workspace and that consumer does not check it — so the manifest-to-witness edge is
currently **inert as a binding**.

**Ownership.** The rule is C2's, and it is normative here. The three missing call-site checks, the
false comment, the absent tests, and the tautological conjunct are **implementation** obligations,
owed by the first change that adopts this amendment; C2 is documentation only and does not edit
Rust. The 2c-C decomposition already recorded the re-hash gap as a live defect and this amendment
does not retract it — it sharpens it from "the walker is missing Req 15.3 checks" to the exact
three-of-four table above, and adds the false comment, the missing mutation control and the
tautological conjunct, none of which had been recorded.

---

# The economic SMT — frozen

Every parameter below was read from source and the vectors at the end were **executed**, not
derived on paper.

## The hash primitive

```text
H_dom(tag, m) = BLAKE3( tag_bytes ‖ 0x00 ‖ m )
```

The `0x00` is the tagged-hash separator and is applied in exactly one place
(`crypto/blake3.rs:167-177`). A tag carrying its own NUL cannot reach it — that fails at
construction. Every derivation in this amendment uses this form; none uses a raw BLAKE3.

## Parameters

```text
ECONOMIC_SMT_HEIGHT = 256        full 256-bit key space, never a parameter
ABSENT_LEAF         = 0x00 × 32  the node value at a leaf position holding nothing
```

`ABSENT_LEAF` is **not** a domain hash. It is thirty-two zero bytes, and it is exactly
`default_node(0)`. A shorter tree is a different tree: a proof that verifies against one must not
verify against the other, which is why the height is fixed rather than carried.

## The two node functions

```text
econ_leaf(k, v) = H_dom(DSM/economic-smt-leaf/v1,  k ‖ v)
econ_node(l, r) = H_dom(DSM/economic-smt-node/v1,  l ‖ r)
```

Separate domains, so a leaf hash can never be read as an internal node.

```text
leaf_node(k, None)    = ABSENT_LEAF
leaf_node(k, Some(v)) = econ_leaf(k, v)
default_node(0)       = ABSENT_LEAF
default_node(h)       = econ_node(default_node(h-1), default_node(h-1))
empty_economic_root() = default_node(256)
```

## Bit ordering — the fact an implementer cannot afford to read backwards

```text
get_bit(k, i) = ( k[i / 8] >> (7 - (i mod 8)) ) & 1
```

**Bit index 0 is the most significant bit of byte 0. Bit index 255 is the least significant bit of
byte 31.** The key is read left to right, most significant bit first.

**Bit index 0 selects the branch at the ROOT. Bit index 255 selects at the DEEPEST level.** The
descent runs `level = 0 .. 255` from the root down, branching on `get_bit(key, level)`.

```text
bit value 0  ->  the node is the LEFT child
bit value 1  ->  the node is the RIGHT child
```

**The sibling array is LEAF-TO-ROOT.** `siblings[0]` is the sibling at the deepest level, the one
selected by bit 255. `siblings[255]` is the sibling adjacent to the root, selected by bit 0. The
producer writes `out[255 - level]`; the verifier reads it back as `level = 255 - i`. The two are
inverse by construction, and this ordering matches the relationship SMT's, so the two proof formats
are not silently transposable.

The fold, stated so it cannot be misread:

```text
current = leaf_node
for i in 0 ..= 255:
    level = 255 - i
    current = if get_bit(key, level) == 0 { econ_node(current, siblings[i]) }
              else                        { econ_node(siblings[i], current) }
root = current
```

## The five-step chain from a leaf state to a root

```text
1.  k  = H_dom(<class key tag>, G ‖ DevID ‖ <class inputs>)      the leaf KEY
2.  v  = H_dom(DSM/economic-leaf-state/v1, CCB(S))               the leaf VALUE
3.  ln = ABSENT_LEAF, or econ_leaf(k, v)                         the leaf NODE
4.  fold ln up the authentication path with econ_node
5.  R_econ
```

Step 2 is easy to miss and getting it wrong changes every root: the value committed at a leaf is
**not** the state's canonical bytes, it is a domain hash **of** those bytes. The state object is
the content; the leaf hash is its position-bound form.

## The four leaf-key derivations

Every one binds `G ‖ DevID` **first**. That is what makes the key space per-identity by
construction rather than by the tree being private: a trader cannot compute — let alone claim — a
position in another identity's economic tree, whatever it knows about that identity's assets. All
inputs are fixed-width 32-byte digests, so the concatenation is unambiguous and carries no length
prefixes.

| Leaf class | Key |
|---|---|
| `0x001F` balance | `H_dom(DSM/economic-balance-key/v1, G ‖ DevID ‖ policy_commit)` |
| `0x0020` vault reserve | `H_dom(DSM/economic-vault-reserve-key/v1, G ‖ DevID ‖ vault_id ‖ policy_commit)` |
| `0x0021` settlement receipt | `H_dom(DSM/economic-settlement-receipt-key/v1, G ‖ DevID ‖ vault_id ‖ receipt_id)` |
| `0x0022` consumed source | `H_dom(DSM/economic-consumed-source-key/v1, G ‖ DevID ‖ source_id)` |

A foreign verifier can compute all four: `G` and `DevID` are fields 1 and 2 of the signed
`0x001B` claim body, and every remaining input is a field of the leaf state object itself.

The conformance vectors for every definition above are published under ruling D.

---

# Register-cell observation — four answers, and an error is never emptiness

## The two enums

```text
MemberCellRead                   one member's ATTRIBUTED answer
    Value(bytes)                 a successful read carrying the cell's exact bytes
    Absent                       an explicit, successful "this cell holds nothing"
    Unavailable                  no usable answer

CellObservation                  what a set of member reads ESTABLISHES
    Claimed(bytes)               a quorum returned byte-identical contents
    EmptyAtQuorum                a quorum explicitly reported no row
    Conflict { distinct }        contradictory non-empty claims, no quorum winner
    Unavailable { attributed, required }   establishes nothing; the caller fails closed
```

**A response the observer could not attribute to the member it asked is `Unavailable`.** Attribution
is therefore a precondition of counting an answer at all, not a property reported alongside it.

## The counting rule

`observe_cell` tallies **everything first and selects nothing in the loop**; only after the tally is
complete is a winner chosen. That ordering is the point — it is what stops iteration order from
deciding an outcome.

```text
Value(b)     -> attributed += 1 ; counts[b] += 1
Absent       -> attributed += 1 ; absent += 1
Unavailable  -> counted as NOTHING
```

`Unavailable` is deliberately excluded from `attributed`: it cannot support a conclusion in either
direction. **This is the rule that makes an error never emptiness.** A cell that three unreachable
members failed to answer is not empty; it is unobserved, and the two must not collapse, because
"empty" is a fact a verifier will act on and "unreachable" is not.

Resolution, in order:

```text
exactly one value at quorum          -> Claimed(that value)
two or more values at quorum         -> Conflict          (impossible under a canonical q;
                                                            this is what a noncanonical q buys)
no winner, but >1 distinct value     -> Conflict
no winner, absent >= quorum          -> EmptyAtQuorum
otherwise                            -> Unavailable { attributed, required }
```

`A, A, B` at q=2 resolves to `Claimed(A)` and never reaches the conflict arm: rows are write-once,
so a minority disagreement beside a quorum winner can never later gain a majority. A minority
dissent is not a conflict.

`EmptyAtQuorum` is **true of the moment it was read** and nothing more. It is not a claim about the
future, and C2 states it that way so no later step treats it as permanent.

## One quorum rule, and where the value comes from

```text
canonical_quorum(n) = n/2 + 1        strict majority -- DERIVED, never chosen
```

Safety needs `2q > n` so any two quorums intersect; strict majority is the smallest `q` that
satisfies it. `require_canonical_quorum` demands **exact equality in both directions**. A smaller
`q` admits two disjoint quorums and therefore two winners. A larger `q` is *safe* but is still a
value no honest producer derives — and accepting it would leave the committed field a place where
discretion lives. Removing the discretion is the point: a signed `1-of-3` must not be honourable
forever by every verifier that trusts the committed value.

The quorum is **supplied by the caller, not computed locally**, because a vault's cells are counted
at the quorum its own signed state commits. A local majority-of-catalog rule is the verifier's
opinion, not the vault's. Callers must have already required that committed value to be canonical.

**The beta profile is not a second rule.** `SOFI_BETA_QUORUM = 2` over `SOFI_BETA_MEMBERS = 3` is
exactly `canonical_quorum(3)`, and a test asserts the identity rather than leaving it to arithmetic
coincidence (`beta_storage_profile.rs:152-160`). Any other cardinality is refused outright: *"a set
size Rev 15 does not speak to is nonconformant, not approximately conformant."*

## Where the economic register's `q` actually comes from — and why that is a defect

The rule above describes what the code *should* count at. It is not what the economic root register
counts at today, and C2 records the gap rather than describing the intent as though it shipped.

```text
DLV / vault path        reads the AUTHENTICATED committed q
                        require_canonical_quorum(vn.storage_set.len(), vn.quorum)
                        provenance.rs:1078-1084          <- correct

economic root register  observe_cell(&reads, set.quorum())
                        StorageSet::quorum() = quorum_for(self.members.len())
                        economic_registers.rs:227, storage_set.rs:150   <- LOCAL member count
```

**`RootRegisterProfile.quorum` has no non-test reader. It is dead.** The pinned profile carries the
threshold and nothing consults it; the operative value is a strict majority of the **locally
resolved** member list. The two coincide at 2 only because `verify_candidate` pins membership to
exactly the three pinned members — so the answer is right by coincidence of the pin, not by
derivation from anything authenticated. Were resolution ever to yield a different member count, the
threshold would silently follow it.

This is the same failure Rev 15 Req 6.10 forbids for Class K — deriving `q` by recomputing a
majority of the resolved set instead of reading it from authenticated data — reappearing in the one
register that has no vault state to read it from.

**Two consequences C2 must close.**

> The threshold an economic register cell is counted at MUST come from the network's normative
> profile, not from the cardinality of whatever member list the verifier happened to resolve. The
> profile's committed `q` MUST be read, and MUST be required canonical for the profile's member
> count.

And the retrieval interface must carry it. `PeerEvidenceFetcher::register_cell` takes neither the
storage set nor the quorum, so the walker cannot state the threshold it is counting at and a fetcher
is free to answer at any `q` it likes. Its sibling `parent_binding_observation` takes both. C2
requires the observation interface to carry `(S, q)` as one authenticated descriptor rather than as
free parameters — the same *make the unsafe path unavailable* discipline the codebase already
applies elsewhere on this walk.

**`observe_cell` does not defend its own precondition.** Its documentation requires callers to have
established that the committed `q` is canonical; the function does not check. With `quorum == 0` it
returns `EmptyAtQuorum` for an empty read set — emptiness manufactured from no members at all, which
is the precise failure class the module exists to remove. The chain is reachable, because
`quorum_for(0) == 0`. C2 requires the observation to refuse a non-canonical or zero threshold rather
than trust its caller.

The single-node development threshold is `#[cfg(test)]` and cannot be reached by any production
build or by a non-test consumer in another crate. It exists so that "development needs one node"
has a named home other than a fallback inside the real function — which is the single change that
would undo the module.

---

# The validated-root walk

## The register key

```text
K_root = H_dom(DSM/trader-economic-root-register-key/v1,
               G ‖ DevID ‖ u64_BE(economic_position))
```

The key **identity-scopes the cell and nothing more.** It is derivable by anyone who knows
`(G, DevID, position)` — all three public — so it confers no exclusivity of its own. Exclusivity
comes from write-once storage plus attribution-checked claimant identity. C2 states this explicitly
because a reader who assumes the key is secret will build the wrong thing: the key is an address,
not a capability.

Note the `u64_BE`. The position is big-endian here, matching CCB's integer convention and *not* the
little-endian foreign grammars 2c-B froze.

## Per position

For each position from the start to the target, the walk:

1. derives `K_root` and observes the register cell at it, at the committed quorum;
2. fetches the admission manifest by content address and **re-checks the address**;
3. fetches the authority evidence and discharges the resolver contract (ruling A), recovering
   `proven_ak` and `network_id`;
4. resolves the network's root-register profile from `network_id` (ruling B), refuses a candidate
   whose membership or re-derived set id is not the pinned one, and requires the claim's committed
   `root_register_storage_set_id` to equal it;
5. requires the claim's `claimant_public_key` to equal `proven_ak` — *the claim's key IS the proven
   AK; storage attribution is not the cryptographic binding*;
6. fetches the transition witness and the successor evidence; and
7. runs the same conjuncts any device runs.

Steps 2, 3 and 6 carry the four addressed fetches, and three of them do not currently discharge the
retrieval obligation — see the retrieval section for the one-by-one table.

## Re-entrancy and what it costs

The walk is **re-entrant**: resolving one identity's position may require walking another's, because
a credit can name a peer's debit. The step budget, memo table, depth counter and in-progress set are
**shared across the whole walk**, not per identity — otherwise a cross-identity fan-out could
multiply work without bound while each individual walk stayed under its own limit.

Two consequences are frozen here:

**A provenance cycle is INVALID.** If the walk re-enters a peer transition already being validated
on the same walk, that is refused: **validation edges must point strictly backward.** This is a
property of the evidence graph, not of the verifier, and it is refusable on its own evidence.

**Memoization must not change a verdict.** The memo is keyed by `(genesis, devid, position)`, and
C2 requires that caching a validated transition is observationally equivalent to re-deriving it. A
memo that returned a result derived under different authority material would make the verdict depend
on visit order.

## Determinism

Two verifiers given the same inputs and the same network parameters must reach the same verdict.
Ruling B removes the configured-fleet divergence; ruling C removes the resource-limit divergence
from *validity* (they may still differ on whether they could finish). The observation rule's
tally-then-select discipline removes iteration order. What remains — and what C2 requires an
implementation not to introduce — is any dependence on map iteration order, wall-clock, or the order
in which members happened to answer.

---

# The identity cuts C2 requires

Registry §2.10 and decomposition ruling 2: **a serialized protobuf is never CCB and must never be
hashed or signed as if it were.** Every content address below is currently computed over prost bytes
and is therefore a required clean beta cut — no dual resolver, no fallback, no accept-either-form.

| Operand | Today | After |
|---|---|---|
| authority-evidence content address | `H_dom(tag, prost bytes)` | `H_dom(tag, CCB(...))` |
| successor-evidence content address | `H_dom(tag, prost bytes)` | `H_dom(tag, CCB(...))` — already declared by 2c-B ruling 3 |
| `0x0030` field 4 target | outer `addr(N, P)` | inner `H_dom(N, P)` — 2c-C1 ruling A |

The two evidence decoders perform prost decode plus re-encode equality — the settlement-wire
discipline, so two byte strings can never decode to one object. **That makes an address exact given
a byte string; it does not make protobuf a legitimate identity basis.** Canonicality and the right
to be an identity are different properties, and §2.10 speaks to the second.

**The transitive consequence, enumerated rather than avoided.** Re-basing an evidence address
changes the `0x001C` manifest that commits it, hence the manifest's own identity, hence the signed
`0x001B` body's field 5. Both enclosing objects keep the same canonical field types and the same
meanings — content addresses of the referenced objects — so **no schema bump of `0x001C` or `0x001B`
is required**, on the same reasoning 2c-B ruling 3 applied. Existing prost-addressed artifacts are
not migrated, grandfathered, or dual-resolved.

**A CCB identity does not always mean a new class.** Per decomposition ruling 2, the smallest
representation that fits is the right one: an object with independent identity and addressing gets a
registered class; a canonical operand contained entirely within another registered object gets its
encoding declared there. What is never permitted is prost bytes as the normative identity.

## What is NOT a cut — and the rule that keeps it that way

The register cell's stored value is an `EconomicRootClaimV1` **prost envelope**, and that is
legitimate: the envelope carries the body's **exact `0x001B` CCB bytes** rather than mirroring the
body as a nested proto message. Mirroring would give one object two canonical forms while the
signature covered only one of them, so the two could disagree while both looked well-formed. The
signature is over `H_dom(DSM/economic-root-claim-sign/v1, CCB)` — never over transport bytes.
Protobuf is carrier here, which is exactly what §2.10 permits.

But the quorum comparison is **byte-identity over those stored bytes**, so the comparison's
soundness rests on the stored bytes being canonical. C2 makes that explicit rather than incidental:

> A register member MUST refuse a claim envelope that does not re-encode to exactly the bytes
> presented. The quorum comparison is byte-identity over stored envelopes, and it is well defined
> only because a non-canonical encoding cannot be stored. A producer retains the exact signed bytes
> and replays them verbatim on every retry; it never re-serializes.

Without that rule the four-valued observation would be unsound in a way that is invisible in
testing: two members holding semantically identical claims under different encodings would read as
`Conflict`, and a claim would be un-observable through no fault of its author.

---

# Live defects this amendment records and routes

These are **implementation** findings, not C2 rulings. They are recorded here because C2 is the
document that defines what these paths are supposed to do, and each one is a place where the shipped
behaviour and the frozen rule disagree.

**The economic register read endpoints never emit the register-incarnation header.**
`x-dsm-register-incarnation` is defined once and stamped on the settlement-slot and binding paths.
Neither `api/economic/root_register.rs` nor `api/economic/faucet_ticket.rs` references it. The
shipped client reader attributes an answer only when the member echoes both its member id and its
register incarnation, so on the live path every economic register read is unattributable. This is
the two-axis read rule of ruling B failing at the producer, and it makes the economic register's
observation degrade to `Unavailable` against a real fleet.

**A divergent write-once faucet cell is delivered as emptiness.** `winning_faucet_ticket` folds the
fetcher's result with `.ok().flatten()`, so `RegisterError::Conflict` — the quarantine case, the
single most important thing a write-once register can tell a verifier — arrives at the walker as
`None`, indistinguishable from "no quorum" and from "nothing there". **This is precisely the
collapse the four-valued observation exists to prevent, reintroduced at the call site**, and it is
the sharpest illustration of why C2 freezes the no-collapse contract rather than trusting callers.

**Write attribution and read attribution use different rules.** A claim counts a member on the node
id alone; a read requires node id **and** register incarnation. A claim can therefore reach
`q`-durability through a member whose corresponding reads can never be attributed. C2's rule is that
the two axes are the same on both sides; the asymmetry is a defect against it.

**The register conformance suite hand-rolls a weaker classifier** than the production reader —
attributing on node id alone and treating a bare 404 as an absence — so it green-lights exactly the
gaps above. A conformance suite that reimplements the thing it is meant to test proves only that two
pieces of test code agree, which is the same error ruling D forbids for vectors.

Each is owed by the implementation change that adopts this amendment. None of them changes a ruling
above; they are what the rulings are for.

# Registry and cross-document edits

- **§3.1 `signature_alg` — corrected (ruling E).** `0x0001` names the DSM BLAKE3-SPHINCS+-SPX256F
  construction explicitly, and the sentence *"the algorithm and the key bytes stand or fall
  together"* is replaced: matching key and signature widths do not identify an algorithm, and these
  particular widths coincide exactly with a different, incompatible one.
- **§2 (new subsection) — the retrieval obligation.** State the fetch-recompute-compare rule as a
  framework-level requirement, since it governs every addressed object and not only the economic
  ones.
- **§2.10 — the one named exception (ruling F).** Record `BindingRecordWireV1` as a frozen
  storage-wire grammar outside CCB, with its Class N argument, explicitly narrow.
- **§15.3 reconciliation.** Rev 15 writes the inner identity as `H(N ∥ P)` — no named hash function,
  no `0x00` separator, and no length discipline for the variable-length namespace. Taken literally it
  is not injective in `N`. The shipped construction is the more specific and is the one C2 freezes;
  the spec text is corrected to match rather than the code changed to match the spec.
- **§3.x network parameters.** Add the `dsm-testnet` root-register profile table: the three
  `(member_id, register_incarnation_id)` pairs, `n`, `q`, and the derived `storage_set_id`, marked
  **normative network parameters**, with the rule that a network absent from the table is unknown
  rather than permissive.
- **§5.2 `StorageSet`.** Cross-reference the profile table as the source of the pinned set for each
  network, so the schema-3 element encoding and the values it is instantiated with sit next to one
  another.
- **§7.** Add the 2c-C2 bullet and mark C2 written.
- **No new §2 primitives.** As in C1, every gap is closed by an in-table declaration under §5.2's
  precedent.

# Closure status

**Canonical identity — FROZEN** for the economic substrate: the SMT parameters, the bit ordering,
the five-step leaf chain, the four leaf-key derivations, `K_root`, and the register profile
identities.

**Authenticated retrieval — FROZEN as a rule, NOT MET by the implementation.** The obligation is
normative here; three of the walk's four fetches do not currently discharge it, and the module
comment asserts that they do. Both are implementation debts, recorded and owned.

**Reusable algorithms — FROZEN**: the four-valued observation, the canonical quorum rule, the
failure taxonomy, and the traversal-limit classification.

**Verification semantics — NOT CLAIMED and NOT C2's.** What a valid DLV continuation *is* remains
2c-C3's `ValidDlvSuccessor`; how results compose into an accepted-successor proof remains 2c-C4's.

**Frontier — NOT ESTABLISHED, and not establishable by this substrate.** The authority contract
proves descent at a bound position and nothing about currency. Any later amendment that needs "no
newer position exists" must obtain it from somewhere other than a presented chain.

**The signature primitive — FROZEN (ruling E)**, and the retry rule that replaces a determinism
requirement is normative. Signing determinism is explicitly **not** frozen.

**The binding record — FROZEN as `BindingRecordWireV1` (ruling F)**, outside CCB, as the single
named storage-substrate exception.

**Formal-model coverage — DISCHARGED under the stated symbolic assumptions (ruling G).**
`lean4/DSMEconomicSmtSeparation.lean` carries obligations 1–7; `tla/DSM_EconRegisterObservation.tla`
carries the concurrent register-observation half, with five deliberate-falsification configs that
are machine-gated on the invariant each must violate. This is coverage of the normative **models**,
not a refinement proof from the Rust — see the claim boundary in ruling G.

**Conformance surface — OWED.** Rev 15 has no conformance row for the economic register, `R_econ`,
the cell observation, or the address construction, because Rev 15 does not mention them. The repo's
existing pattern maps spec conformance rows to in-tree tests; without new rows every ruling here is
prose with no surface that can go red. The adopting change owes the rows.

# Scope

**Documentation only. No Rust, no proto, no tests.** The implementation debts this amendment
records — the three missing retrieval checks, the false module comment, the prost identity cuts, and
`0x0030`'s outer-to-inner form — are owed by the changes that adopt it, each of which must carry the
conformance vectors published under ruling D.

# Verification

1. **Every algorithmic fact was read from source, and every vector was executed.** The SMT bit
   ordering, the `get_bit` convention, the sibling array direction, the five-step chain and the four
   leaf keys were read directly rather than taken from a research summary; the vectors were produced
   by running the shipped functions and deleted afterwards, leaving the tree clean.
2. **The vectors carry their own controls.** Reversing the sibling array, reversing the key bytes,
   and swapping the `econ_node` argument order each produce a different root, and all three were
   executed. A single expected root can be reproduced by an implementation that is wrong twice; the
   controls are what make that detectable.
3. **Two self-consistency identities hold** — `econ_node(ABSENT_LEAF, ABSENT_LEAF) == default_node(1)`
   and `ABSENT_LEAF == default_node(0)` — and the `EconomicBalanceState` CCB measured **44 bytes**,
   exactly the width 2c-C1 §5.28 froze. That is an independent check that C1's field table and the
   shipped encoder still agree.
4. **The P0–P6 finding was verified negatively before being asserted.** The specification file was
   confirmed present and non-empty (2,652 lines, and `15.3` occurs three times) before concluding
   that `P0` occurs zero times. An absence claim from a search that silently failed is exactly the
   error this programme has already published once.
5. **The Req 15.3 table is one-by-one, not a summary.** Each of the four fetches was traced to its
   call site, and both verify functions were checked for an internal re-derivation before the
   absence was recorded. `authority_evidence_addr` and `successor_evidence_addr` exist and are simply
   not called on the consume path.
6. **Research ran read-only and was proved so.** `git status --porcelain` and `git diff --exit-code`
   were clean before the fan-out, during it, and after it. This is the process rule adopted after a
   subagent silently repaired the defects it had been sent to audit during 2c-C1, causing a correct
   finding to be retracted. No finding in this amendment rests on a tree another agent could write.
7. **Self-contradiction sweep** for `no / never / always / only / first / every`, and specifically
   that no sentence claims C2 decides `ValidDlvSuccessor`, that no sentence publishes a traversal
   limit as normative, and that no sentence elevates `P0`–`P6` into a SoFi interface.
8. **Every finding that reached a ruling was re-verified at source by me, not taken from a research
   summary.** The signature construction (BLAKE3 substitution, the deterministic randomizer, `OsRng`
   only in keygen), `RootRegisterProfile.quorum` having no non-test reader, `StorageSet::quorum()`
   resolving to a local member count, `.ok().flatten()` dropping `Conflict`, the incarnation header
   being absent from both economic handlers, zero registry hits for the binding record, and zero
   economic references in `lean4/` and `tla/` — each was confirmed directly. **One of those checks
   corrected this amendment's own draft**: the quorum section originally described the pinned
   profile's threshold as the operative one, which is false.
9. **Scope proof** — `git diff --stat` shows `docs/` only.
