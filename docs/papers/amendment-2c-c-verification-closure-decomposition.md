# Amendment 2c-C — verification closure (decomposition)

Status: **DECOMPOSED into 2c-C1…2c-C4. Do not begin any of them from this document alone.**
2026-09-07.

Normative and encoder-free, per the registry preamble. This document is the decomposition, the
three governing rulings, and the routing of researched material to the sub-amendment that owns it.
It claims neither encoding nor verification closure.

## Context

2c-A (merged) froze the settlement bundle's structure. 2c-B closed `MarketTerms` field 6, so a
conformant market `b` is now constructible. Both were **encoding** closure. 2c-C is the amendment
that carries **verification** closure — and a four-dimension source audit established that it
cannot be written as one document.

The evidence for splitting is not stylistic:

```text
~26 open decisions across four dimensions   (2c-A had 7 rulings; 2c-B had 4)
four dimensions that are separable in fact, not merely in presentation
§2 framework extensions REQUIRED before the economic classes can be expressed at all
```

The originally chartered asymmetry — *record every class number, but fully specify only the
transitive closure `TA_B` reaches* — remains the scope guard. It is not, by itself, a sufficient
packaging rule once the dimensions were shown to have different prerequisites and different failure
modes.

---

## The four sub-amendments

```text
2c-C1 — Canonical framework + namespace
    §2 type-system / encoding extensions needed by the economic classes
    absorb 0x001B–0x0030 into the registry
    class/schema allocation and burns
    stale scope/header corrections

2c-C2 — Verification substrate / algorithms
    immutable addressing
    SMT proof semantics and bit ordering
    quorum / register-cell resolution
    P0–P6 primitives and authority-walk mechanics
    other algorithmic facts every later verifier consumes

2c-C3 — ValidDlvSuccessor
    full V_n -> V_{n+1} semantic predicate
    preserved fields
    permitted mutations
    operation-specific authorization
    reconcile against the existing Rev-15 requirements

2c-C4 — Accepted-successor / TA_B verification closure
    assemble the already-frozen primitives into the complete
    third-party verification chain
    prove the economic accepted-successor/root correspondence
    close the remaining verification walk
```

### Dependency graph

```text
C1
 ↓
C2 ─────┐
 ↓      │
C3      │
 └──────┴──→ C4
```

**C4 consumes C3, not only C1 and C2.** `TA_B` verification relies on `ValidDlvSuccessor` wherever
the accepted successor is a DLV continuation, so the chain C4 assembles is incomplete without C3's
predicate. An earlier draft of this decomposition described C4 as "assembling C1+C2"; that is
corrected here.

Why four and not two: *"framework + everything else"* still leaves the hard half carrying algorithm
definitions, DLV successor semantics and full acceptance closure together, and those have different
failure modes. **C2 answers how verification primitives work. C3 answers what constitutes a valid
DLV continuation. C4 answers how those results compose into the final accepted-successor proof.**

---

## Ruling 1 — the four-way split

Taken. The fact that 2c-C was originally chartered as one amendment is not a reason to preserve
that packaging after source research exposed four separable dimensions and ~26 unresolved
decisions. Freezing 26 rulings in one review cycle is how cross-contamination and stale language
get in — the exact failure eliminated over several rounds in 2c-A and 2c-B.

## Ruling 2 — protobuf bytes never carry protocol identity

Registry §2.10 says a serialized protobuf is never CCB and must never be hashed or signed as if it
were. Three shipped identities violate it: the economic register cell's identity, the quorum
comparison operand, and `AuthorityEvidenceV1`'s content address.

**These are implementation nonconformances, not precedent.** The normative rule for C1:

> Existing protobuf-derived identities in the economic substrate are implementation
> nonconformances, not precedent. Absorption into the CCB registry replaces those identity
> derivations with canonical CCB derivations. Protobuf may remain as transport after the cut, but
> its serialized bytes have no protocol identity, ordering, comparison, hashing, signing, or
> content-addressing authority.

```text
Economic register-cell identity   -> derive from a frozen CCB representation
Quorum comparison operand         -> compare canonical CCB bytes, or a digest derived from them,
                                     never protobuf serialization bytes
AuthorityEvidenceV1 content addr  -> H(domain ‖ CCB(AuthorityEvidenceV1)), not H(prost_bytes)
```

**A CCB identity does not always mean a new top-level class.** C1 uses the smallest canonical
representation that fits the framework:

- a real protocol object with independent identity and addressing → a **registered CCB class**;
- a canonical tuple or operand entirely contained within another registered object → its
  **canonical CCB encoding defined there**;
- in neither case may prost bytes be the normative identity representation.

That distinction prevents class proliferation without weakening §2.10.

**Clean-cut doctrine, as in 2c-B:**

```text
old prost-addressed economic artifacts  !=  grandfathered canonical artifacts
no dual resolver
no prost fallback
no "accept either encoding"
```

Where re-basing an identity changes objects above it, **C1/C2 enumerate the transitive identity
cut** rather than preserving the old address.

**Rejected:** a "canonical transport protobuf" tier. It creates a second canonicalisation system
alongside CCB, after which every reviewer must ask whether an object's serialization is ordinary
protobuf or special canonical protobuf — the exact ambiguity §2.10 removed. **Also rejected:**
deferral. C1 exists so C2–C4 build verification on stable identities; unresolved prost identities
would leave the quorum walk and the `TA_B` chain resting on addresses whose canonical meaning is
unsettled.

## Ruling 3 — one quorum rule, and `q` committed in authenticated state

Four shipped Rust quorum rules disagree for every `n ≠ 3`, and the economic root register's quorum
is committed in no signed object — `PeerEvidenceFetcher::register_cell` has no parameter for it. A
foreign verifier therefore cannot derive it, which defeats the point of a deterministic
third-party-verifiable register observation:

```text
foreign verifier receives the same economic-root lineage
        -> but q comes from LOCAL CONFIGURATION
        -> verifier A may accept, verifier B may reject
```

The DLV side already has the right pattern: an authenticated `V_n` carries both `storage_set` and
`quorum`, and a foreign verifier derives both from committed state. The economic root register does
the same kind of thing — its threshold must come from something **in the authenticated walk**,
never from ambient node configuration.

```text
resolve authenticated descriptor
derive S and q
read exactly S
require attributable matching responses >= q
```

The ruling splits three ways, and all three parts are normative:

```text
protocol:            exactly one normative q rule
authenticated state: commits the actual q used by this register instance
beta profile:        currently permits only n = 3, q = 2
```

**The beta admission rule stays restricted to `n = 3, q = 2` even after the general function is
specified.** That reconciles the four shipped formulas without widening the live threat model.

**Rejected:** leaving `q` to the network profile — two verifiers with different profiles reach
different conclusions about one lineage, which is the failure the register exists to prevent.
**Also rejected:** recording only Rev 15 Req 6.13's single point (`n=3 ⇒ q=2`) and nothing else,
which leaves the four disagreeing rules waiting to become a protocol fork the moment another
cardinality appears.

---

# Routing — which finding each sub-amendment owns

| Finding | Owner |
|---|---|
| §2 type extensions: a fixed-count array (`0x001E` field 3 is 256 × 32 bytes, **no count prefix**), ordering predicates §2.4/§2.5 cannot state, a mutually-exclusive optional whose type is a union of classes | **C1** |
| Absorb `0x001B`–`0x0030` into §3 and §5 — sixteen shipped economic classes with no registry row | **C1** |
| The three prost-identity nonconformances of ruling 2, and the transitive identity cut each causes | **C1** |
| Record `(0x0026, 1)` and `(0x0027, 1)` as burned | **C1** |
| Two stale scope headers, and one stale test comment | **C1** |
| Whether `0x002A`–`0x002F` get §3 rows | **C1** (open) |
| Immutable addressing — reconcile with Rev 15 §15.3, and the `inner` vs `addr` per-field ruling | **C2** |
| SMT parameters: height 256, `ABSENT_LEAF`, `econ_leaf`/`econ_node`, leaf-to-root sibling ordering, the four leaf-key derivations, `K_root` | **C2** |
| The quorum rule of ruling 3, the register-cell observation taxonomy, and where committed `q` lives | **C2** |
| P0–P6 as normative predicates | **C2** |
| Walk budgets: are `WALK_STEP_BUDGET = 512` and `CROSS_IDENTITY_DEPTH_CAP = 32` protocol or local policy? | **C2** (open) |
| Golden vectors — whether C2 publishes literal `empty_economic_root()`, one `econ_leaf`, one `econ_node`, one `immutable_addr` triple, one `K_root` | **C2** (open) |
| `ValidDlvSuccessor`: per-field disposition for all fifteen `VaultStateV2` fields, both operation kinds | **C3** |
| The four unvalidated `DlvSettle` fields routed here by 2c-B — `sigma`, `settler_public_key`, `settler_devid`, `signature` | **C3** |
| Whether `ValidDlvSuccessor` takes `V_{n+1}` as **input** or **derives** it | **C3** (open, and consequential) |
| Field 13 on an owner close; fields 14/15 on a close; `β` semantics; the arithmetic discipline | **C3** (open) |
| The walk as a numbered normative chain, ending at `ValidatedEconomicRoot` | **C4** |
| Trusted start, position-0 semantics for a foreign lineage, offline-arm refusal | **C4** (open) |
| The leaf-key derivation family stated as **class-dispatched and open**, so 2c-D can add `0x0032`'s key without reopening C2 | **C2**, consumed by **C4** |

## Explicitly not any 2c-C sub-amendment

- `TA_B` `0x0011`'s field table, `0x0032`, the bundle-acceptance leaf — **2c-D**, and `TA_B`'s
  table must be *re-derived* once the leaf authenticates `b`.
- `0x0031`'s Rust class constant and its collision test — assigned by 2c-B to *"the first
  implementation change that implements `0x0031`"*.
- `verify_market_leg_policies` and the SoFi Def 4.1 / Req 4.4 / Req 4.6 token-policy conjunct —
  reached from inside the walk but belonging to neither 2c-C nor 2c-D.
- Any `0x000E` / `0x0033` / `0x000F` / `0x0010` / `0x0031` field number, type, ordering or presence
  rule — permanently frozen by 2c-A and 2c-B under §2.8.

---

# Live defects the audit surfaced

These are not scope items. They are conformance failures in shipped code, recorded here so the
sub-amendment that reaches each one fixes it rather than codifies it.

## The walker violates Requirement 15.3, and its own doc comment says otherwise

Rev 15 §15.3 fixes the address construction, and Req 15.3 places the re-hash obligation on the
consumer:

> *"Every Class K consumer must re-hash returned bytes and compare the result with the requested
> canonical address before decoding or verifying higher-level protocol content."*

The foreign-verifier walk in `economic/peer_lineage.rs` re-hashes **one of four** objects. The
admission manifest is checked (`:355-358`); the authority evidence (`:365`), the transition witness
(`:409`) and the successor evidence (`:414`) are fetched by address with no comparison. The trait's
own documentation claims the opposite:

> *"immutable objects whose bytes re-hash to their address. The walker re-checks the address
> anyway — a fetcher cannot substitute bytes."* (`:60-62`)

So a fetcher **can** substitute bytes for three of the four. This is a violation of an existing
requirement, not a rule 2c-C invents — **C2** owns the correction.

## The economic namespace has no declarative burn channel

`ccb::schema::BURNED` and `is_burned` are never referenced anywhere under `dsm/src/economic/`.
`(0x0026, 1)` and `(0x0027, 1)` are declared burned in prose in `credit.rs` and are **enforced
structurally** — `economic/decode.rs` pins every economic class with exact envelope matching, and
both classes ship at schema 2, so a schema-1 body is refused on the wire. The gap is therefore
**declarative, not enforcement**: the pairs are absent from `schema::BURNED`, no test asserts the
refusal, and the registry's burned-schema paragraph omits them. **C1.**

## Two stale scope headers and one stale test comment

Two files declare a scope narrower than their actual contents. `dsm/src/ccb/mod.rs` opens
*"## Scope — Exactly the classes `c_n` depends on"* over a seven-row table, while the same file
allocates the substrate classes, the sixteen economic classes and the six reserved numbers.
`dsm/src/economic/decode.rs:15-18` disclaims the manifest — *"The claim and manifest (`0x001B` /
`0x001C`) are the register and admission layer and decode with that work, not here"* — while that
same file decodes `0x001C`, `0x0029` and `0x0030`.

And `dsm/tests/economic_root_primitives.rs:692` still asserts
*"0x0030 is LIVE (faucet distribution); 0x0031 is the next free class"* after 2c-B allocated
`0x0031`. That string is a **test assertion**, so it is the one item here that will fail loudly
rather than rot quietly — the first change to touch `0x0031` trips it. **C1.**

## Four class-less surfaces a class-number enumeration structurally cannot find

`EconomicProofArtifactV1`, `ReserveConsumptionEvidenceV1` and `SettlementPaymentEvidenceV1` each
carry a doc note reading *"transport proto, no CCB class — the faucet-claim/settlement-slot
precedent"*, and two fetcher-trait inputs (`faucet_ticket_cell`, `anchored_policy_bytes`) have no
class either. They are reached by the walk. **C1** decides whether each needs a class under ruling
2's smallest-representation test; **C4** states what the walk requires of them.

---

# Corrections to earlier documents

**`ValidDlvSuccessor` is reconciliation, not invention.** Rev 15 already carries most of the
relation: §6.1 enumerates a normative successor checklist (vault id, parent generation, parent state
commitment, parent reserves digest, storage-set identity, committed threshold, encumbrance proofs,
deterministic state arithmetic, conservation, byte identity of the successor, plus kind-specific
market and release/close conjuncts and the terminal-close retire-and-credit-once obligation); §5.2
gives the completion witness; §8 gives the encumbrance add/carry/consume/solvency rules for field
10; §13 gives `β_{n+1} = β_n − 1`; §4.1 already forecloses advancing `r_o` in the beta profile.
Earlier framing in this programme treated C3 as a blank sheet. It is not, and C3 must open with
that reconciliation rather than a fresh derivation.

**Rev 15 Req 6.10/6.13 does not contradict the shipped quorum helper.** Req 6.13's `n=3 ⇒ q=2`
agrees with it, and Req 6.10 expressly permits *"a versioned quorum rule whose output for the
committed S is unique"*. The real disagreement is **among four shipped Rust rules**, not between
spec and code. Ruling 3 resolves it in that framing.

**Part of the walk is already normative.** `amendment-2c-settlement-and-evidence-profile.md`
§1.2–§1.3 states the trusted start, the register winner, address-equality re-derivation, the P0–P6
step, the claim-signing-key rule, the register-set rule, `sigma_dsm` under the proven AK, and
`advance_validated`'s derived-equals-registered rule. C4 assembles and completes it; it does not
start from nothing.

---

# Closure status

**Encoding closure — not claimed.** C1 must land the §2 extensions and the `0x001B`–`0x0030`
absorption first.

**Verification closure — not claimed, and it is the point of the whole sub-programme.** C2 makes
the primitives reproducible, C3 fixes the successor relation, C4 closes the chain.

**Formal-model coverage — not claimed.** No formal model governs this layer.

# Scope

**Documentation only.** No Rust, no proto, no tests, no encoder. Each sub-amendment states its own
two closure statuses and may claim neither on behalf of another.

# Sequencing

```text
2c-C1  ->  2c-C2  ->  2c-C3  ->  2c-C4  ->  2c-D
```

Encoder work on `0x0031` may begin after 2c-B, per its own sequencing block. **Production
acceptance of the market bundle remains gated on C3 and C4**, per 2c-B's
encoding-closure-is-not-production-enablement rule.
