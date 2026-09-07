# Amendment 2c-A — Freeze `B` and `T_v`

Status: **A-STAGE NORMATIVE STRUCTURE FROZEN. MARKET ENCODING REMAINS BLOCKED ON 2c-B FIELD 6.
NO ENCODER FOLLOWS FROM THIS DOCUMENT ALONE.** 2026-09-07.

Normative and encoder-free, per the registry preamble.
Governs `docs/papers/ccb-object-registry.md` classes `0x000E`, `0x0033`, `0x000F`, `0x0010`,
and implements the already-defined `0x000B`.

## Context

Amendment 2c decomposed into four (`amendment-2c-settlement-and-evidence-profile.md`).

2c-A is first because **everything downstream names `b`**, while the shipped implementation still
computes the would-be bundle identity over prost protobuf bytes even though registry §3 defines:

```text
b = H(DSM/settlement-bundle || CCB)
```

The outer canonical structure therefore has to stop moving before the downstream acceptance and
receipt objects can be specified against it.

**2c-A fixes the derivation and A-stage canonical structure of `b`; it does not claim that a
conforming market `b` is constructible from 2c-A alone.** `MarketTerms.recovery_material` is
mandatory, but the nested recovery class itself is owned by 2c-B. Until 2c-B fixes that class
number, schema and canonical bytes, complete `Canon(B)` for the market shape is intentionally
uninstantiable.

2c-A therefore:

- freezes the field numbers, outer structure and semantics of `0x000E SettlementBundle`;
- freezes the field numbers, outer structure and semantics of `0x0033 MarketTerms`;
- fully defines `0x000F ConsumedDlvTransition`;
- fully defines `0x0010 DlvProofMaterial`;
- gives `I` (`0x000B`) its first real producer and deterministic satisfaction predicate; and
- fixes the equation by which `b` is derived from the eventual complete CCB.

§2.8 makes every field number permanent on first ship, so this is an opening audit, not a
transcription. Registry §7 refuses an "absorb as shipped" tier.

---

## What the audit already established

**Def 6.14 gives twelve members in order** (`sofispecs:872-887`), and its following prose is
unusually prescriptive about `T_v`:

> "the parent side of Tv is the exact cn of the consumed state and nothing else; the vault
> identifier, parent generation, parent state commitment hn and parent reserves digest are NOT
> carried, because every one of them is a field of Vn and is read from the authenticated state
> that cn identifies."

The shipping `VaultTransitionV1` violates **every one of those four exclusions**, and five of the
twelve bundle members carry a placeholder rather than the fact they name. Transcribing that layout
would freeze permanently the exact aliases Def 6.14 wrote a paragraph to forbid.

**Consequence to state plainly:** the CCB cut invalidates every would-be `b` produced by the
shipping protobuf path. That is a clean beta cut, not a migration. No current protobuf-derived
identifier is a conformant CCB `b`, and the first conformant **market** `b` cannot be constructed
until 2c-B closes the mandatory recovery-material class.

### Settled by research, no ruling needed

- **`version` (member 1) is deleted.** §2.1's envelope already carries the schema version. No
  other §5 table carries a second body copy of its frozen schema number.

- **`{T_v}` is a §2.4 set ordered by complete element CCB.** §5.11 already retired the
  order-by-in-element-identifier argument. Once `vault_id` is removed from the transition wrapper,
  the shipping sort is not merely disfavoured but impossible.

- **Vault uniqueness survives without a new carried identifier.** `K(B)` must contain no duplicate
  `k_v` under Def 6.17, and:

  ```text
  k_v = H_dom(DSM/binding-keyset, c_n)
  ```

  Two transitions on one DLV would consume the same current parent. §18.5 explicitly says a
  bound-but-unrealized market settlement does **not** advance to a new parent, so both transitions
  would claim the same `c_n` and therefore collide.

  §18.5's "a smaller number when the route reuses a DLV" is about the blast-radius count, not a
  licence to consume one DLV twice in the same bundle.

- **`bundle_signatures` moves into `0x000F` as per-transition `close_authorization`.** The
  shipping bundle-level collection has no deterministic signature-to-transition mapping and works
  around that by banning mixed bundles. Per-transition placement supplies the association by
  construction.

- **`storage_set_id` and `q` are deleted.** Their former justification, "derivable but not
  recoverable by a verifier holding only `B`", ceased to hold once `T_v.successor` became the
  complete `V_{n+1}`. The intent remains, but as the complete nested `TradeIntent`, not a
  separately carried digest.

- **`recovery_material` and `selected_route` cannot remain opaque protobuf bytes.** Every opaque
  byte field in the shipping proto is a path by which protobuf could be smuggled into `b`.
  `selected_route` becomes a nested canonical `Route`. `recovery_material` becomes a mandatory
  nested object inside `MarketTerms`; 2c-B owns that nested object's class and canonical form.

- **`nonce` is excluded from the satisfaction predicate.** It enters the commitment `I`, but it
  does not alter execution outcome. `TradeIntent.nonce` and `RouteCommitmentBody.nonce_x` are
  independent and neither may be derived from the other. Neither nonce is settlement replay
  protection; Req 6.23's fence supplies that property.

- **The leg-chaining rule must be written.** Rev 15 does not state it completely. Direction
  propagates from the intent, not from guessing which side of constant-product arithmetic appears
  to have increased.

---

## What Rev 15 already specifies for `I`, and what it does not

| Intent field | Status |
|---|---|
| `max_hops`, `max_fanout`, `k` | fully specified — cite, do not restate |
| `min_out` | inequality stated; "total out" needs a precise definition |
| `max_fee` | inequality stated; no comparable scalar is defined |
| `token_in`, `token_out`, `amount_in` | no complete equality predicate exists |

The last row is security-relevant. A route could satisfy every expressly stated bound while
swapping the wrong asset unless these equalities are made normative.

---

# Owner rulings — 2026-09-07

## Ruling 1 — `total_fee` is the counterfactual in `token_out`

`max_fee` is denominated in `token_out` base units.

```text
out_actual(r)
    = the final token_out quantity obtained by the selected route under every
      authenticated DLV parent's actual committed fee policy.

out_zero_fee(r)
    = the final token_out quantity obtained by deterministically re-simulating
      THE SAME selected route from THE SAME authenticated parents and THE SAME
      initial amount, replacing only each market fee rate with zero.

total_fee(r)
    = out_zero_fee(r) - out_actual(r)

Validity:
    out_zero_fee(r) >= out_actual(r)
    total_fee(r)    <= I.max_fee
```

"Same route" means the same topology, same selected DLVs and same allocation structure. It does
**not** mean freezing the originally committed intermediate output quantities.

On a multi-hop route, the zero-fee pass recomputes each hop sequentially. Additional output from
removing an upstream fee therefore propagates into downstream hops.

The zero-fee pass is a **counterfactual verifier calculation only**. It:

- does not assert that any vault actually has a zero-fee policy;
- does not create another candidate successor;
- does not alter authenticated parent state; and
- exists solely to derive one intent-bound scalar denominated in the trader's requested output
  asset.

User-facing meaning:

> `max_fee` is the maximum reduction in final `token_out` attributable to the selected route's
> committed AMM fees.

Rejected alternatives:

- nominal per-leg fee sum: units differ between hops;
- summing basis points: arithmetically wrong;
- retyping `max_fee` as basis points: changes the already-frozen `u64` semantic;
- leaving it unenforced: violates the §16.4 trader contract.

---

## Ruling 2 — the route lives in `B`; `Q` lives in the receipt publication set

`selected_route` is nested `0x000D` schema 2.

That permits a bundle verifier to discharge the route-local portion of `Satisfies(I,R,r)` without
fetching a separately published route object.

`Q` (`0x0017` schema 2) remains in the Def 14.2 receipt publication set. The third-party Req 14.5
verifier uses it to establish that the executed route came from the exact committed route set.

The boundary is:

> **`B` proves exactly which route was executed. The receipt/evidence set proves that route came
> from the exact committed choice set and intent.**

---

## Ruling 3 — beta carries exactly one `T_v`, but the field remains a set

This is a beta profile restriction, not a type change.

```text
|{T_v}| = 1
```

The field remains plural and remains a §2.4 set. Future support for multi-DLV atomic settlement
therefore does not require changing the field from scalar to collection.

The unblock condition is explicit:

> Enabling multi-DLV atomic settlement requires a separately specified ordinary-DSM operation
> whose authenticated trader successor and economic write set cover every `T_v` in the bundle.

A consequence follows:

`B` carries the DLV continuations it realizes. A route consuming three DLVs therefore requires
three `T_v` values.

So beta's one-`T_v` restriction forces the **settled beta market route** to:

```text
exactly one leg
exactly one bare 0x0015 Allocation
fanout = 1
```

This narrows what one beta bundle may make binding-final. It does **not** narrow what the routing
layer may discover, compare or reason about.

Multi-hop fee/chaining rules remain defined for the future general profile, but beta does not
exercise them.

---

## Ruling 4 — delete "and generation" from Def 6.14

Do not reinterpret "generation" as the economic position.

Those are different coordinate systems.

Corrected wording:

> For the initiating trader, `trader_parent` is the exact ordinary DSM bilateral parent-state
> commitment from which the market transaction is constructed, and `trader_successor` is the exact
> already-prepared and signed bilateral successor commitment representing the trader's side of the
> exchange.

Therefore:

```text
B.trader_parent
    = exact ordinary-DSM bilateral parent-state commitment

B.trader_successor
    = exact prepared C_dsm+

economic_position
    = later untrusted locator for starting the economic validity walk
```

No generation counter is carried in `B`.

The parent commitment identifies the exact ordinary DSM chain position. Req 6.23's fence supplies
exclusivity. DSM §4.3 deliberately keeps counter-like metadata out of successor identity.

---

## Ruling 5 — the nesting stands

Do not introduce digest indirection merely to avoid schema propagation.

If `b` is to identify:

- the exact trader intent;
- the exact selected route;
- the exact trader continuation; and
- the exact DLV continuation,

then changing the canonical meaning of one of those nested objects **should** change the bytes of
a newly constructed bundle.

Insulating the outer bundle by replacing complete objects with digest references would reintroduce
the exact problem this audit is eliminating: independently encodable statements of the same fact.

So:

> `b` is not merely a pointer to the facts of settlement. Its complete canonical bytes commit the
> facts themselves.

The depth buys three important properties:

1. Tier-1 intent verification is bundle-local.
2. `T_v` carries the actual proposed DLV continuation, not a locator for it.
3. `b` has one canonical semantic closure instead of depending on unbound external preimages.

For beta the actual object remains tightly bounded because one bundle contains one `T_v`, one leg
and one allocation.

Schema propagation is legitimate protocol-versioning cost, not an architectural defect.

---

## Ruling 6 — one optional nested `MarketTerms` subobject

The owner close carries no market machinery.

Earlier versions tried to make market-specific members mandatory in the same flat bundle shape.
That forces nonsensical values for close:

- dummy `TradeIntent`;
- dummy `Route`;
- zero `X`;
- false trader coordinates;
- fake recovery material.

That is rejected.

Making all market fields independently optional is also rejected because it creates a
combinatorial malformed-state space.

The optionality belongs at one subobject boundary:

```text
SettlementBundle
    market_terms?       // one optional nested object
    transitions
```

Shape validity:

```text
Market:
    market_terms PRESENT
    every T_v.close_authorization ABSENT

OwnerClose:
    market_terms ABSENT
    |{T_v}| == 1
    T_v.close_authorization PRESENT

anything else:
    INVALID
```

A separate peer class for owner close was considered and rejected. The protocol intentionally has
one binding-bundle abstraction with two valid shapes. Splitting it would unnecessarily propagate
into:

- `b`;
- QuorumBind value semantics;
- receipt/evidence logic;
- §15.8 inventory language; and
- every consumer selecting bundle kind.

`MarketTerms` is nested by value and is not a separately addressed immutable artifact.

---

## Ruling 7 — delete `storage_set_id` and `q` from the bundle

Their old justification disappeared when `T_v.successor` began carrying complete `V_{n+1}`, whose
state already contains `storage_set` and `quorum`.

More importantly, neither value copied into the proposed bundle may become authoritative for
binding.

QuorumBind uses the **authenticated consumed parent**:

```text
resolve c_n -> authenticated V_n

S = V_n.storage_set
q = V_n.quorum
```

Bundle validity then requires:

```text
V_{n+1}.storage_set == V_n.storage_set
V_{n+1}.quorum      == V_n.quorum
```

The parent remains authoritative because it is the state whose liquidity is being occupied.

Trusting a proposer-selected `V_{n+1}.quorum` would permit the candidate to choose a convenient
quorum.

The rejected "anti-substitution" argument is also wrong: anti-substitution is established by
equality between authenticated `V_n` and proposed `V_{n+1}`, not by adding a third copy into `B`.

---

# Member accounting

Def 6.14's twelve members map as follows:

| Def 6.14 member | Disposition |
|---|---|
| 1 `version` | deleted; §2.1 envelope carries schema |
| 2 `storage_set_id` | deleted; `V_n.storage_set` authoritative |
| 3 `q` | deleted; `V_n.quorum` authoritative |
| 4 `I` | `MarketTerms` field 1 as complete nested `TradeIntent`; digest derived |
| 5 `X` | `MarketTerms` field 2 |
| 6 `selected_route` | `MarketTerms` field 3 |
| 7 `trader_parent` | `MarketTerms` field 4; "and generation" deleted |
| 8 `trader_successor` | `MarketTerms` field 5 |
| 9 `{T_v}` | `SettlementBundle` field 2 |
| 10 `{P_v}` | moves inside corresponding `T_v` |
| 11 `bundle_signatures` | moves inside `T_v` as `close_authorization` |
| 12 `recovery_material` | `MarketTerms` field 6, mandatory |

Def 6.14's flat tuple therefore becomes two nested objects:

```text
SettlementBundle
    market_terms?
    transitions {T_v}

MarketTerms
    intent
    X
    selected_route
    trader_parent
    trader_successor
    recovery_material
```

Everything only the market path possesses is grouped inside `MarketTerms`.

An owner close carries none of it.

---

## Why `{P_v}` cannot remain parallel to `{T_v}`

If `{T_v}` and `{P_v}` are both §2.4 sets, each is independently sorted by complete element CCB.

There is therefore **no stable index correspondence** between the two sets.

The choices are:

1. nest each `P_v` inside the `T_v` it proves; or
2. make `P_v` repeat `c_n` so the verifier can join them.

Option 2 reintroduces the exact alias Def 6.14 forbids.

Therefore `P_v` is nested in `T_v`.

This gives:

- one proof slot per transition;
- unambiguous association;
- no repeated parent identifier; and
- canonical zero-material representation through ordinary optional-field absence.

---

# §5.19 `SettlementBundle` — class `0x000E`, schema 1

The identity derivation is:

```text
b = H_dom(DSM/settlement-bundle, CCB(SettlementBundle))

tx_id        = b
value_digest = b
```

**This derivation is final here; complete market instantiation is not.**

A market bundle contains mandatory `MarketTerms.recovery_material`, whose nested class is fixed by
2c-B.

Therefore:

> 2c-A defines the identity function and every A-stage outer byte that feeds it, but no conforming
> market producer may emit `B` or compute a final market `b` until 2c-B closes the mandatory nested
> recovery type.

The owner-close shape does not carry `MarketTerms` and is unaffected by that particular encoding
dependency.

### Field table

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `market_terms` | optional nested `0x0033` schema 1 | presence marker always emitted; present iff Market |
| 2 | `transitions` (`{T_v}`) | set of `0x000F` schema 1 | §2.4 complete-element order; duplicates invalid; beta cardinality exactly 1 |

### Shape rule

```text
Market:
    B.market_terms PRESENT
    |B.transitions| == 1            // beta
    every T_v.close_authorization ABSENT

OwnerClose:
    B.market_terms ABSENT
    |B.transitions| == 1
    T_v.close_authorization PRESENT

otherwise:
    INVALID
```

The bundle-level discriminator is **field 1**.

A decoder therefore knows the bundle shape immediately after decoding the first field and does not
have to inspect a later transition to decide whether earlier optional fields were legal.

### Owner close carries no fabricated market state

An owner close carries:

- no `TradeIntent`;
- no `Route`;
- no `X`;
- no trader parent;
- no trader successor;
- no market recovery material; and
- no trader-parent fence.

Req 6.30 expressly says the beta owner close has no remote leg, no owner acceptance artifact, no
owner-side Req 6.23 fence and no owner-bound-but-unrealized state.

### `storage_set_id` and `q` are not bundle fields

Execution authority:

```text
T_v.parent_binding = c_n

resolve c_n -> authenticated V_n

binding_storage_set = V_n.storage_set
binding_quorum      = V_n.quorum
```

Successor consistency:

```text
V_{n+1}.storage_set == V_n.storage_set
V_{n+1}.quorum      == V_n.quorum
```

No third copies exist.

### `vault_id` is not repeated

There is no bundle-level or transition-wrapper `vault_id`.

The identifier appears in the canonical graph inside the nested `VaultStateV2`, where it is
authoritative.

An earlier statement that "`vault_id` appears nowhere in the object graph" was wrong once complete
`V_{n+1}` became nested. The correct rule is:

> `vault_id` is not redundantly restated beside commitments that already commit it.

### Vault uniqueness

For each transition:

```text
k_v = H_dom(DSM/binding-keyset, T_v.parent_binding)
```

`K(B)` contains no duplicate `k_v`.

Therefore two transitions cannot consume the same parent.

### Clean beta cut

The shipping bundle identity is not grandfathered.

The shipping implementation hashes protobuf bytes, while §2.10 explicitly says protobuf transport
bytes are not CCB.

Therefore no current shipping identifier is a conformant `b`.

`0x000E` is a first CCB ship, not a schema burn.

The first conformant **market** `b` becomes constructible only after 2c-B closes mandatory
`MarketTerms.recovery_material`.

---

# §5.20 `MarketTerms` — class `0x0033`, schema 1

> **A-stage status:** class number, field numbers, ordering, meanings and mandatoriness are frozen
> here. Encoding closure is **not** yet claimed for schema 1 because field 6 is a mandatory nested
> object whose canonical class/schema are fixed by 2c-B.

Consequently:

```text
2c-A alone
    != complete Canon(MarketTerms)
    != complete market Canon(B)
    != final market b
```

A complete market bundle becomes constructible only after 2c-B lands.

`MarketTerms` is nested by value in `SettlementBundle` and is never separately content-addressed.

It therefore adds no new independently published object to §15.8's immutable-object inventory.

## Namespace allocation

`0x0033` is selected by a namespace audit, not by reading the stale registry table.

The audit established:

```text
0x0001 .. 0x0030    allocated/reserved with no usable vacancy
0x0031              claimed in amendment 2c for 2c-B
0x0032              claimed in amendment 2c for 2c-D
0x0033              first unclaimed usable number
```

`0x0003` and `0x0014` are burns.

`0x002A`–`0x002F` are structurally reserved and protected by `ccb::reserved`.

The registry is behind the code for the economic substrate classes in the `0x001B`–`0x0030`
region. That broader divergence remains 2c-C's absorption work.

A separate hazard also remains: several classes exist normatively in the registry but have no Rust
class constant protecting their numbers. 2c-C must close that namespace-enforcement gap.

## Field table

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `intent` | nested `0x000B` schema 1 | complete `TradeIntent`; `I` derived |
| 2 | `route_set_commitment` (`X`) | `digest32` | `H_dom(DSM/route-set, CCB(Q))` |
| 3 | `selected_route` (`r`) | nested `0x000D` schema 2 | complete executed route |
| 4 | `trader_parent` | `digest32` | exact ordinary DSM bilateral parent commitment |
| 5 | `trader_successor` | `digest32` | exact prepared `C_dsm+` |
| 6 | `recovery_material` | mandatory nested object; class/schema fixed by 2c-B | exact non-secret material needed to reconstruct parent → successor |

### Field 6 is structurally mandatory

A market bundle may not become binding-final without enough non-secret canonical material to
reconstruct exactly:

```text
trader_parent -> trader_successor
```

after a crash.

The market settle is not reconstructible from `C_dsm+` alone. The continuation requires material
such as the canonical operation/relation preimage, signature material and entropy that are not
derivable merely from composed economic state.

Previously this was represented as an optional field plus a validity rule saying it must be
present.

That is weaker than necessary.

The correct structure is:

```text
MarketTerms exists
    => recovery_material field exists
```

There is no encodable market `MarketTerms` without field 6.

An owner close has no `MarketTerms`, so it has no market recovery-material slot at all.

### `I` is derived from the object, not independently carried

```text
I = H_dom(DSM/intent, CCB(MarketTerms.intent))
```

This resolves the earlier contradiction where the bundle carried only a digest but Tier 1
attempted to read:

- `token_in`;
- `token_out`;
- `amount_in`;
- `min_out`;
- `max_fee`;
- `max_hops`;
- `max_fanout`;
- `k`.

A digest has no such fields.

The complete intent therefore lives in `B`, and `I` is a deterministic derivative.

There is one authoritative representation.

### `I` and `X` are never aliases

The shipping path currently aliases placeholder intent material to `X`.

That is invalid.

They commit different objects under different domains:

```text
I = H_dom(DSM/intent, CCB(TradeIntent))

X = H_dom(DSM/route-set, CCB(Q))
```

No producer may populate one with the other.

### Trader coordinates

```text
MarketTerms.trader_parent
    = exact ordinary DSM bilateral parent-state commitment

MarketTerms.trader_successor
    = exact already-prepared C_dsm+
```

These are not vault coordinates.

DLV `c_n` and trader parent remain separate:

```text
DLV c_n
    -> liquidity occupancy / QuorumBind resource key

trader_parent
    -> ordinary DSM continuation exclusivity / Req 6.23 fence
```

---

# §5.21 `ConsumedDlvTransition` — class `0x000F`, schema 1

Def 6.14's governing constraint:

> The parent side of `T_v` is the exact `c_n` and nothing else. The vault identifier, parent
> generation, parent state commitment and parent reserves digest are not separately carried because
> they are already committed by `V_n`.

## Field table

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `parent_binding` (`c_n`) | `digest32` | exact consumed DLV state commitment |
| 2 | `successor` (`V_{n+1}`) | nested `0x0001` schema 4 | complete proposed canonical successor |
| 3 | `proof_material` (`P_v`) | optional nested `0x0010` schema 1 | absent for beta constant product |
| 4 | `close_authorization` | optional `bytes` | present iff owner close |

Derived:

```text
c_{n+1} = H_dom(DSM/vault-state, CCB(T_v.successor))
```

Do not carry both the complete successor and a second independently encoded successor digest.

---

## Parent/successor asymmetry

The asymmetry is deliberate.

### Parent

The parent is referenced by digest because:

- it already exists;
- it is realized authoritative state;
- it is independently authenticated;
- it is the source of QuorumBind storage-set/quorum authority;
- it is the input to `k_v`; and
- Def 6.14 expressly requires the exact `c_n` and nothing else.

### Successor

The successor is completely specified before binding, but is not yet authoritative realized DLV
state.

`B` commits a **proposed exact successor**.

Realization later determines whether that exact state becomes economic state.

This encodes the occupancy/realization distinction directly:

```text
binding-final
    => exact future state committed
    != successor already realized
```

A digest-only successor would require the verifier to obtain a preimage from some separately
published object. Before realization there is no independent authoritative successor source; the
binding bundle itself is the proposal publication.

Therefore the complete successor is nested by value.

An earlier statement that the successor "exists nowhere until realization" is withdrawn. Once
embedded in a binding-final bundle, its canonical bytes plainly exist. The correct statement is:

> The successor is specified before binding and may be published inside `B`, but it is not
> authoritative realized DLV state until realization.

---

## Reserve deltas are not carried

The earlier rule:

> "`T_v` carries the complete DLV successor, exact reserve deltas and required witnesses"

is amended to:

> **"`T_v` carries the complete DLV successor and required witnesses."**

Reason:

```text
V_n reserves
V_{n+1} reserves
```

already determine the movement.

The selected route already carries the executed allocation quantities.

A third independently encodable copy inside `T_v` would create another fact that could disagree.

---

# Successor-validity boundary

Now that the complete successor is authoritative **input** from `B`, constant-product
re-simulation cannot be described as "the validity check."

It proves reserve arithmetic only.

It does not prove invariance of:

- vault identity;
- token pair;
- market policy;
- fee policy;
- release policy;
- owner authority position;
- encumbrance set;
- storage set;
- quorum; or
- any other field that the successor must preserve.

The ownership split is therefore explicit.

## 2c-A owns structural checks

```text
V_{n+1}.parent_state_commitment == T_v.parent_binding

V_{n+1}.generation == V_n.generation + 1

V_{n+1}.storage_set == V_n.storage_set

V_{n+1}.quorum == V_n.quorum
```

For owner close:

```text
V_{n+1}.reserve_a == 0
V_{n+1}.reserve_b == 0
```

The predecessor relation can partly be checked bundle-locally because `V_{n+1}` includes its
parent commitment.

## 2c-C owns full semantic validity

```text
ValidDlvSuccessor(V_n, V_{n+1}, operation)
```

must enumerate:

- every preserved field;
- every mutable field;
- every permitted mutation;
- operation-specific rules; and
- all authority constraints.

This is not optional cleanup.

For example, `owner_authority_transition_digest` is invariant across a market successor because an
offline-owner market execution may not silently advance the owner's authority position.

Arithmetic alone would not detect that attack.

---

## Close preflight is stronger

Owner close is one-phase because its complete release successor is already owner-authorized before
occupancy is taken.

Therefore:

> The complete close candidate must verify under the authority committed by the exact consumed
> parent **before the first mutating QuorumBind operation**.

Never:

```text
bind
-> later discover authorization cannot verify
```

because that leaves the vault permanently occupied by an unrealizable close.

---

## Bundle-local predecessor check

Because `T_v.successor` is complete:

```text
T_v.successor.parent_state_commitment
    == T_v.parent_binding
```

is checkable from the bundle bytes themselves.

A successor descending from a different parent is refused before a deep external validity walk.

The generation increment still requires resolving `V_n`.

---

# Bundle shape versus transition authorization

There is one bundle-shape discriminator:

```text
B.market_terms
```

There is one per-transition owner-authorization marker:

```text
T_v.close_authorization
```

They are not competing sources of truth.

```text
B.market_terms PRESENT
    => every T_v.close_authorization ABSENT

B.market_terms ABSENT
    => |{T_v}| == 1
    => that T_v.close_authorization PRESENT
```

The decoder learns the bundle shape from `0x000E` field 1.

Field 4 is then checked for consistency with a shape already known.

Two earlier claims are withdrawn:

1. per-transition authorization is **not** the only way to derive bundle shape once complete
   successor state is inline; and
2. field 4 is **not** itself the bundle-shape discriminator.

What survives is the security reason for field 4:

> `close_slot_commitment` is a public derivation anyone can compute. It can classify a candidate,
> but it cannot authorize one.

The owner signature is the fact that must be committed.

---

# `close_authorization`

## §2.9 does not forbid this field

§2.9 forbids an object's **own signature over itself** from being inside that same object's CCB
because that creates encoding/signing circularity.

`close_authorization` is a signature over a foreign object: the DSM close-operation preimage.

Ordering is total:

```text
construct canonical DlvClose operation
-> sign operation
-> place signature in T_v.close_authorization
-> encode T_v
-> encode SettlementBundle
-> compute b
```

No CCB self-signing cycle exists.

---

## Only the signature is carried

The close operation itself is reconstructed from authenticated state.

The reconstruction obtains from `V_n` and `V_{n+1}`:

- `vault_id`;
- both leg policies;
- both leg amounts;
- parent sequence;
- new sequence;
- fee basis points; and
- the state necessary to determine the exact unilateral close.

`mode = Unilateral` is fixed.

Nothing protobuf-encoded enters `b`.

The exact canonical close-operation preimage is a declared forward dependency on **2c-B**.

2c-A freezes:

- field number;
- field type;
- optionality; and
- shape semantics.

2c-B freezes exactly what that signature authenticates.

---

## Canonical encoding does not require deterministic signatures

Canonical encoding means:

> Given the same exact field values, the encoded bytes are identical.

It does **not** mean:

> Every conforming signer must independently produce the same signature bytes.

The current repository's SPHINCS+ implementation happens to be deterministic, but this amendment
refuses to depend on that property.

Reasons:

1. DSM's current BLAKE3-substituted construction is not standardized SLH-DSA.
2. Standardized SLH-DSA commonly supports hedged/randomized signing.
3. The repository itself warns that the current implementation is unaudited for production
   financial use.
4. Current deterministic-signature test coverage does not itself prove every future signing backend
   behaves identically.
5. Signature determinism would not prove the rest of candidate construction is deterministic
   anyway.

Normative rule:

> Once a close candidate is prepared, its exact authorization bytes are frozen and reused across
> every retry, recovery and rebind. A conforming producer never re-signs an already-prepared close
> candidate.

Therefore the owner-close `b` is fixed at preparation time by the exact authorization bytes.

The amendment does **not** claim that two independent constructions of the same semantic close must
produce the same `b`.

---

# §5.22 `DlvProofMaterial` — class `0x0010`, schema 1

Beta's only declared pricing family is:

```text
family_id      = 0x0001
family_version = 1

CONSTANT_PRODUCT_EXACT_INPUT
```

For that family, a foreign verifier already has every required fact from:

- authenticated `V_n`;
- complete proposed `V_{n+1}`;
- selected route;
- `Allocation`;
- committed market policy;
- committed fee policy; and
- consumed encumbrance claim.

No irreducible additional proof bytes remain.

Therefore:

> `DlvProofMaterial` schema 1 has zero fields.

The complete bare CCB envelope is still defined.

When nested through optional `T_v.proof_material`, beta always encodes the optional field as
absent.

No fake proof data is manufactured merely to populate the type.

---

## Future proof material requires schema propagation

An earlier proposal said that a future `0x0010` schema could change without changing `0x000F`.

That is false.

A nested object's complete CCB includes its schema version.

Therefore:

```text
0x0010 schema 2
    -> 0x000F schema bump
    -> 0x000E schema bump
```

Field 3 buys a permanently assigned **slot and semantic role**, not immunity from future
enclosing-schema changes.

---

# Full nested-schema propagation

Every nested canonical type propagates through its immediate enclosing object.

Correct graph:

```text
0x000B TradeIntent
    -> MarketTerms schema bump
    -> 0x000E SettlementBundle schema bump

0x000D Route
    -> MarketTerms schema bump
    -> 0x000E SettlementBundle schema bump

0x0015 Allocation
0x0016 AllocationBundle
0x000A nested market/route material
    -> through Route where applicable
    -> MarketTerms schema bump
    -> 0x000E SettlementBundle schema bump

2c-B recovery class
    -> MarketTerms schema bump
    -> 0x000E SettlementBundle schema bump


0x0001 VaultStateV2
    -> 0x000F ConsumedDlvTransition schema bump
    -> 0x000E SettlementBundle schema bump

0x0002 StorageSet
0x0005 / 0x0007 / 0x0009 / 0x000A
    -> through VaultStateV2 where applicable
    -> 0x000F schema bump
    -> 0x000E schema bump

0x0010 DlvProofMaterial
    -> 0x000F schema bump
    -> 0x000E schema bump
```

Nothing nested reaches `0x000E` directly any more.

Its two immediate canonical children are:

```text
MarketTerms
ConsumedDlvTransition
```

---

# Versioning rule

> **A schema-1 `SettlementBundle` accepts exactly the nested class/schema combinations fixed by its
> field table. A future schema change to a nested object does not retroactively change schema-1
> bundle interpretation. Using a newer nested schema requires a corresponding new schema of every
> enclosing object whose canonical field type changes.**

No previously computed `b` mutates.

No previously computed `b` is rehashed.

For example:

```text
TradeIntent v1
    -> MarketTerms v1
    -> SettlementBundle v1
    -> b1 identifies exactly those schema-1 bytes

TradeIntent v2
    -> MarketTerms v2
    -> SettlementBundle v2
    -> b2 identifies the newly constructed schema-2 bytes
```

"Propagation" describes which schema a **newly constructed** object must use.

It never means that a historical identifier changes.

---

## Identity permanence versus decode permission

These are separate questions.

### Identity permanence

A `b` computed over exact bytes permanently identifies those exact bytes.

### Decode permission

Whether production software may continue decoding an old schema after it is burned is governed
separately by §2.8.

§2.8 says no production path:

- decodes;
- accepts;
- emits; or
- falls back to

a burned schema.

Therefore 2c-A does **not** promise perpetual production decodability of schema-1 bundle bytes.

The audit/dispute-resolution question for a future first `0x000E` burn remains explicitly open for
the amendment that performs that burn.

Nothing among these four new classes is burned today:

```text
0x000E SettlementBundle
0x0033 MarketTerms
0x000F ConsumedDlvTransition
0x0010 DlvProofMaterial
```

All four are first ships at schema 1.

`0x000E` canonical closure is downstream of `MarketTerms` and `0x000F`, and transitively of the
nested classes enumerated above at the exact schema versions named by their enclosing field tables.

It is not downstream of those classes' future versions.

---

# `Satisfies(I, R, r)`

The predicate is divided into three tiers.

## Tier 1 — selected-route and intent economics

The complete intent is inside:

```text
B.market_terms.intent
```

The selected route is inside:

```text
B.market_terms.selected_route
```

Authenticated `c_n -> V_n` resolution supplies each consumed DLV's token pair and pricing family.

Tier 1 requires:

```text
direction(1).token_in      == I.token_in

total_in(1)                == I.amount_in

direction(h).token_out     == I.token_out

total_out(r)               >= I.min_out

total_fee(r)               <= I.max_fee

len(r.legs)                <= I.max_hops

|leg_i.allocations|        <= I.max_fanout
    for each AllocationBundle leg

bare Allocation leg
    => fanout = 1
```

Beta's one-leg/one-allocation restriction is stronger than these general upper bounds.

## Tier 2 — selected route belongs to committed route set

Requires `Q` from the receipt/evidence set:

```text
|Q.route_set.routes| <= I.k

r in Q.route_set.routes
```

Membership is complete `Route` CCB equality, not an implementation-local identifier comparison.

## Tier 3 — exact route set and intent commitment

Requires:

```text
X == H_dom(DSM/route-set, CCB(Q))

Q.intent == H_dom(
    DSM/intent,
    CCB(B.market_terms.intent)
)
```

The predicate applies only to the market shape.

Owner close has no `I`, no `R`, no `r`, no `Q` and no `X`; `Satisfies` is not evaluated.

---

## Nonce rule

`TradeIntent.nonce` enters the computation of `I`.

`RouteCommitmentBody.nonce_x` enters its own route-commitment construction.

They are independent.

```text
TradeIntent.nonce           != derived-from RouteCommitmentBody.nonce_x
RouteCommitmentBody.nonce_x != derived-from TradeIntent.nonce
```

Neither changes execution economics.

Neither is replay protection.

Req 6.23's parent fence is replay/continuation protection.

---

# Leg-chaining rule

Direction is determined from the intent.

Never infer it from AMM arithmetic.

For each route leg, resolve every allocation's consumed parent:

```text
c_n -> V_n -> P_M
```

to obtain the unordered token pair.

Then:

```text
in(1) = I.token_in

in(i) must be one token in leg i's resolved pair

out(i) = the other token in that pair

in(i+1) = out(i)

out(h) = I.token_out
```

All allocations within one leg must resolve to the same token pair and same direction.

Quantities:

```text
total_in(i)
    = sum(delta_in) over leg i allocations

total_out(i)
    = sum(delta_out) over leg i allocations

total_in(1)
    = I.amount_in

total_in(i+1)
    = total_out(i)

total_out(r)
    = total_out(h)
```

The route-stated final output must equal the result of deterministic pricing re-simulation.

---

## Why direction cannot be inferred from constant-product arithmetic

The reserve transition alone does not provide a general unambiguous semantic direction.

Small integer reserves and rounding make heuristic direction inference especially unsafe.

The intent therefore determines direction first; arithmetic verifies the quantities under that
direction.

---

# Zero-fee multi-hop pass

Both actual and counterfactual passes use:

- identical route topology;
- identical consumed DLVs;
- identical allocation structure;
- identical pricing-family id/version;
- identical authenticated parent reserves;
- identical initial input;
- identical checked-integer arithmetic rules; and
- identical evaluation order.

Only the market fee term is replaced with zero.

For a future multi-allocation leg, if a zero-fee upstream hop yields additional input to the next
leg, that larger input is redistributed over the same allocation structure according to the actual
split ratios:

1. preserve each member's exact rational share;
2. floor each share;
3. distribute residual base units one each in ascending complete-element-CCB order.

This makes the counterfactual deterministic.

**Beta does not exercise this clause** because beta is one leg and one allocation.

The rule is specified now but must not be described as empirically covered by beta conformance.

---

# What 2c-A changes in the registry

## §3 object table

Four new/changed A-stage field tables are introduced:

```text
§5.19  SettlementBundle        0x000E
§5.20  MarketTerms             0x0033
§5.21  ConsumedDlvTransition   0x000F
§5.22  DlvProofMaterial        0x0010
```

Status after 2c-A:

```text
0x000F -> defined
0x0010 -> defined

0x000E -> A-stage table frozen, encoding blocked on 2c-B
0x0033 -> A-stage table frozen, encoding blocked on 2c-B field 6
```

`0x000E` and `MarketTerms` must **not** be marked fully encoding-closed until the mandatory
recovery class exists.

The status pointers for `0x000E`, `0x000F` and `0x0011` were corrected in the same change; the
registry had been sending them to unrelated sections.

---

# Prerequisite registry corrections

The registry's `VaultStateV2` and `StorageSet` schema statements **were** stale relative to shipped
code, and are corrected by this amendment.

Verified source state:

```text
VaultStateV2
    class 0x0001
    shipped schema = 4
    old schemas 1,2,3 burned

StorageSet
    class 0x0002
    shipped schema = 3
    old schemas 1,2 burned
```

The registry described older schema versions before this correction.

This must be corrected in the same normative change because:

```text
0x000F field 2
    nests complete 0x0001 CCB

complete nested CCB
    includes nested schema version
```

Freezing `0x000F` against stale `VaultStateV2` schema 3 would freeze a burned schema on first
ship.

Therefore:

```text
0x000F field 2 = nested 0x0001 schema 4
```

The same history demonstrates the version-propagation rule in production:

```text
StorageSet 2 -> 3
    forced
VaultStateV2 3 -> 4
```

A future `VaultStateV2` schema 5 similarly requires:

```text
0x000F schema bump
    -> 0x000E schema bump
```

---

# Registry section numbering

The next free §5 subsection is **§5.19**, not §5.18.

§5.18 is already "Genesis sentinels."

Therefore the four new sections are:

```text
§5.19 SettlementBundle
§5.20 MarketTerms
§5.21 ConsumedDlvTransition
§5.22 DlvProofMaterial
```

---

# §6 blocked-table update

After 2c-A:

- remove the old `0x0010` blocker;
- remove the old `0x000F` blocker;
- remove the generic claim that `0x000E`/`0x000F` are blocked by member types and `0x0010`;
- replace it with the exact remaining blocker:

  ```text
  0x000E and 0x0033
      remain encoding-blocked only because
      MarketTerms field 6 requires 2c-B's canonical recovery class
  ```

- leave `0x0012 TradeDigest` unchanged;
- leave `0x0011 TraderAcceptance` blocked and point it to 2c-B/2c-C/2c-D.

---

# Burns

No **new** burn is introduced by these four first-ship classes:

```text
0x000E schema 1
0x0033 schema 1
0x000F schema 1
0x0010 schema 1
```

The same registry edit records existing burns for the stale `0x0001` and `0x0002` histories.

Those are documentation of cuts that already happened, not burns caused by 2c-A.

`TradeIntent` §5.5 is unchanged.

2c-A supplies its first actual producer and the satisfaction predicate, but changes none of its
fields.

---

# Closure status

## Encoding closure

### Fully closed in 2c-A

```text
0x000F ConsumedDlvTransition
0x0010 DlvProofMaterial
```

These can be encoded from the specifications frozen here and the already-defined nested classes
they reference.

### Structurally frozen but intentionally not encoding-closed

```text
0x0033 MarketTerms
0x000E SettlementBundle market shape
```

Reason:

```text
MarketTerms field 6
    = mandatory nested recovery object

recovery object's:
    class number
    schema
    canonical fields
    canonical bytes

are owned by 2c-B
```

Because field 6 is mandatory, this is a real closure dependency.

Therefore:

> **2c-A alone cannot produce a complete market `MarketTerms`, complete market `SettlementBundle`,
> or final market `b`.**

2c-A freezes:

- field 6's number;
- field 6's semantic role;
- its mandatoriness;
- its position in canonical ordering; and
- the fact that it is a nested canonical object.

2c-B freezes its concrete nested class.

---

## Worked encoding status

2c-A can carry a **complete owner-close encoding example**, including:

- `market_terms = absent`;
- one `0x000F` transition;
- nested complete `VaultStateV2`;
- absent beta `proof_material`;
- exact frozen `close_authorization` bytes.

For the market shape, 2c-A can carry only a **worked A-stage layout** through the closed fields:

```text
SettlementBundle
  -> MarketTerms
       -> TradeIntent
       -> X
       -> Route
       -> trader_parent
       -> trader_successor
       -> recovery_material [MANDATORY SLOT, TYPE CLOSED BY 2c-B]

  -> ConsumedDlvTransition
       -> parent_binding
       -> VaultStateV2
       -> absent proof_material
       -> absent close_authorization
```

2c-A must **not invent placeholder bytes** for field 6.

The complete market byte vector is a mandatory:

```text
2c-A + 2c-B closure test
```

after 2c-B assigns the recovery class.

---

## Encoding determinism versus construction determinism

Canonical encoding promises:

> Given the same exact field values, canonical bytes are identical.

That is distinct from claiming that independent parties necessarily generate identical inputs.

For owner close, the signature bytes are frozen at candidate preparation.

For market, no independent-construction claim is made until 2c-B closes recovery material.

After A+B, the required property is:

> Once the exact prepared trader successor and exact canonical recovery material are fixed, every
> reconstruction produces the same `B` bytes.

That is the property crash recovery and rebind require.

The stronger statement:

> "Any two independent constructions of the same semantic trade always produce the same bundle"

is **not** claimed.

---

# Verification closure

Verification closure is not claimed by 2c-A.

Open dependencies remain:

## 2c-B

- exact accepted-successor/recovery canonical class;
- canonical market recovery preimage;
- canonical close-operation authorization preimage.

## 2c-C

- complete `ValidDlvSuccessor(V_n,V_{n+1},operation)`;
- immutable-addressing rules needed by foreign verification;
- P0–P6 authority-walk closure;
- transitive economic/substrate class absorption.

## 2c-D

- final trader-acceptance object and bundle-level acceptance leaf closure.

These are named explicitly so the absence of verification closure cannot be mistaken for
completion.

---

# Burn doctrine versus historical decoding

One question is recorded but not settled here:

> When a future `0x000E` schema is burned, should old bundle bytes remain decodable solely for
> audit/dispute inspection even though no production acceptance path may use them?

§2.8 currently says keeping a burned schema readable in production would be a coexistence plan.

2c-A does not legislate a different answer.

Identity permanence remains separate:

```text
historical b
    permanently names historical bytes
```

whether or not future production code is permitted to decode them.

Nothing among the four new classes is burned today.

---

# Formal-model coverage

**Not claimed.**

There is no economic-layer formal model currently governing this amendment.

2c-A does not imply that a TLA+/Lean model exists or has been skipped.

The absence is recorded rather than silently elided.

---

# Deliverable

Normative documents only:

```text
docs/papers/amendment-2c-a-bundle-and-transition.md

docs/papers/ccb-object-registry.md
    §3 status/table updates
    §5.1 / §5.2 schema corrections
    §5.19–§5.22 additions
    §6 blocker updates

docs/papers/amendment-2c-settlement-and-evidence-profile.md
    mark 2c-A A-stage normative structure written
    record remaining 2c-B encoding dependency
    mark §0d question settled where applicable
```

No Rust.

No proto.

No tests.

No encoder.

Shipping code is evidence of current behavior only; it is never authority over the canonical
protocol definition.

---

# Verification

A normative document has no software board, so the verification performed here is documentary and
canonical.

## 1. A-stage byte determinism

### Owner close

Hand-encode the complete owner-close bundle twice by two independent readings of §2.1–§2.7.

Confirm identical bytes for:

- `market_terms` absence marker;
- one-element §2.4 transition set;
- `parent_binding`;
- complete nested `VaultStateV2`;
- beta `proof_material` absence;
- exact frozen `close_authorization`.

### Market

Hand-encode the A-stage market skeleton through every already-closed nested object.

Confirm:

- `market_terms` presence;
- complete `TradeIntent`;
- `X`;
- complete `Route`;
- trader parent;
- trader successor;
- field 6 occurs in the fixed canonical position and is mandatory;
- one-element transition set;
- complete `V_{n+1}`;
- `proof_material` absent;
- `close_authorization` absent.

Do **not** fabricate:

- recovery class number;
- recovery schema;
- recovery payload.

A complete market byte vector is deferred to the mandatory A+B closure test.

At that test:

> "same market settlement" means the same exact prepared trader successor and the same exact
> canonical recovery material, not merely the same economic intent.

The required property is:

```text
same exact prepared candidate
+ same exact canonical recovery material
    -> identical B bytes
    -> identical b
```

---

### Worked owner-close layout (complete)

Verified by encoding it twice from two independent readings of §2.1–§2.7. **The fixture is pinned
so the total is determined:** zero encumbrance claims, a three-member storage set with 6-byte
member ids, `iteration_budget` absent, and an `SPHINCS_PLUS_SPX256F` signature of **49,856 bytes**
(§3.1; `dsm/src/crypto/sphincs.rs:19`, asserted at `:1552`). Both encoders produce the same
**50,330 bytes**:

```text
0x0007 MarketPolicy                        72
0x0009 ReleasePolicy                        8
0x000A FeePolicy                            8
0x0005 EncumbranceSet, zero claims           8
0x0002 StorageSet schema 3, three members  134
0x0001 VaultStateV2 schema 4               423
0x000F ConsumedDlvTransition            50,321   (423 + 49,856 signature + 42 frame)
0x000E owner-close SettlementBundle     50,330
```

The signature dominates by two orders of magnitude, which is the honest shape of an owner close
and worth seeing before anyone budgets for one.

```text
00 0e                       0x000E SettlementBundle
00 01                       schema 1
00                          field 1 market_terms  ABSENT  -> OwnerClose
00 00 00 01                 field 2 transitions   count = 1
  00 0f                       0x000F ConsumedDlvTransition
  00 01                       schema 1
  <32 raw>                    field 1 parent_binding c_n   (digest32: NO length prefix)
    00 01 00 04                 field 2 successor = 0x0001 VaultStateV2 SCHEMA 4
    <32><32><32>                  f1 g_o, f2 d_o, f3 vault_id
    <8><8><8>                     f4 generation, f5 reserve_a = 0, f6 reserve_b = 0
    00 07 00 01 ...               f7  market_policy   nested 0x0007
    00 09 00 01 ...               f8  release_policy  nested 0x0009
    00 0a 00 01 ...               f9  fee_policy      nested 0x000A
    00 05 00 02 ...               f10 encumbrances    nested 0x0005 schema 2
    00                            f11 iteration_budget ABSENT
    <32>                          f12 parent_state_commitment h_n   == field 1 above
    <32>                          f13 owner_authority_transition_digest
    00 02 00 03 ...               f14 storage_set     nested 0x0002 SCHEMA 3
    <4>                           f15 quorum
  00                          field 3 proof_material  ABSENT (beta)
  01 <u32 len> <sig>          field 4 close_authorization PRESENT -> owner close
```

Four properties this layout demonstrates rather than asserts:

- **the absent optional is emitted, not skipped** (§2.3) — byte 4 is `0x00`, so a close and a
  market bundle can never share a byte string by field shifting;
- **`parent_binding` carries no length prefix**, because `digest32` is a distinct type from
  `bytes` (§2.2);
- **the nested successor is `0x0001` schema 4**, not the schema 3 the registry described before
  this amendment corrected it; and
- **`V_{n+1}.parent_state_commitment == T_v.parent_binding` is checkable inside `Canon(B)` with
  no fetch** — the two 32-byte runs are both present in the bundle bytes.

`0x0010`'s bare envelope is `00 10 00 01`, exactly 4 bytes, and never appears on the wire in beta
because field 3 encodes absence.

### Worked market layout (A-stage, stops at field 6)

```text
00 33 00 01                 0x0033 MarketTerms schema 1        offset    0,   4 bytes
  00 0b 00 01 ...           field 1 intent  nested 0x000B      offset    4, 136 bytes
  <32 raw>                  field 2 X       digest32           offset  140,  32 bytes
  00 0d 00 02 ...           field 3 route   nested 0x000D      offset  172, 100 bytes
  <32 raw>                  field 4 trader_parent              offset  272,  32 bytes
  <32 raw>                  field 5 trader_successor           offset  304,  32 bytes
  >>> field 6 recovery_material                                offset  336
      class and schema are 2c-B's. NO placeholder is emitted. <<<
```

336 bytes are fully determined; the object is not. A five-field `MarketTerms` is not a conformant
object, because field 6 is mandatory — which is precisely why **a complete market
`SettlementBundle` and a final market `b` are blocked on 2c-B**, and why this amendment carries no
complete market vector.

## 2. §2.8 field-number audit

For all four new tables:

```text
0x000E
0x0033
0x000F
0x0010
```

confirm:

- every field number is new within its class;
- no number is reused;
- no new burn is required.

Also confirm:

```text
0x0010 zero-field bare envelope = 4 bytes

0x0000 untouched

0xFF00..0xFFFF untouched
```

---

## 2b. Namespace re-audit at write time

Run the source and repo-wide class-number sweep again immediately before writing the canonical
files.

Confirm:

```text
0x0033 still unclaimed

0x0031 still reserved by amendment 2c for 2c-B

0x0032 still reserved by amendment 2c for 2c-D
```

The namespace audit found no usable vacancy below `0x0031`, so stale assumptions are a live
collision risk.

---

## 2c. Nested-schema audit

For every already-defined nested class referenced by the **four** new tables, read the shipped
`const SCHEMA` directly from `dsm/src/ccb/`.

Do not trust the registry as the sole source because this audit already found it stale for:

```text
0x0001 VaultStateV2
0x0002 StorageSet
```

The unresolved 2c-B recovery class is excluded from this check because it does not yet exist; that
absence is the declared encoding blocker, not an error to hide.

---

## 3. Citation re-read

Open and re-read every SoFi specification range cited by the amendment, including:

- Def 6.14 and following prose;
- Def 6.17;
- Req 6.15;
- Req 6.23;
- Req 6.30;
- §9.1–§9.3;
- §16.4;
- §18.5.

Do not rely on search snippets for the final normative write.

---

## 4. Cross-reference sweep

Verify:

```text
0x000E status -> correct §5.19 / blocker reference
0x0033 status -> correct §5.20 / 2c-B blocker
0x000F status -> correct §5.21
0x0010 status -> correct §5.22
0x0011 status -> correct 2c-B/2c-C/2c-D references
```

Ensure no new `### 5.N` heading collides with existing §5.18 "Genesis sentinels."

---

## 4b. Self-contradiction sweep

Search the amendment for universal/superlative language including:

```text
no
never
always
only
first
forever
the only way
nothing
every
```

Re-check each against the final tables.

Specific drafting errors already found and therefore worth pinning:

1. "no `vault_id` anywhere in the object graph" — false once complete `V_{n+1}` is nested;
2. "per-transition authorization is the only way to derive BundleShape" — false after nesting the
   successor;
3. "field 4 is the bundle-shape discriminator" — false after `MarketTerms`;
4. "old `b` remains interpretable forever" — conflates identity permanence with production decode
   permission;
5. "`storage_set_id` and `q` remain because a bundle-only reader cannot recover them" — false after
   complete `V_{n+1}`;
6. "two independent semantic-trade constructions necessarily produce identical market bytes" —
   stronger than what recovery material permits;
7. "2c-A alone freezes a complete market `b`" — false until 2c-B closes mandatory field 6.

No such stale statement may survive into the canonical amendment.

---

## 5. Scope proof

```text
git diff --stat
```

must show documentation-only changes.

Expected surfaces:

```text
docs/papers/
docs/plans/   only if the mirror/status pointer requires synchronization
```

No Rust, proto or test file is part of 2c-A.

---

## 6. Decision-record completeness

All seven owner rulings must appear in the amendment's decision record, with rejected alternatives
where material:

1. counterfactual `max_fee`;
2. route in `B`, `Q` in publication set;
3. beta exactly one `T_v`;
4. delete "and generation";
5. keep deep nesting;
6. one optional `MarketTerms`;
7. delete `storage_set_id` and `q`.

A later reader must not be able to mistake any of these for an unresolved design question.

---

# Final 2c-A boundary

After this amendment is written:

```text
FROZEN / COMPLETE:
    0x000F field table and encoding
    0x0010 field table and encoding

FROZEN AT A-STAGE:
    0x000E field numbers / shape / identity derivation
    0x0033 field numbers / semantics / mandatoriness
    TradeIntent satisfaction predicate
    beta T_v cardinality
    close-versus-market shape rule
    parent/successor structural checks
    schema-propagation rules

STILL BLOCKED:
    complete MarketTerms encoding
    complete market SettlementBundle encoding
    final conformant market b

BLOCKER:
    2c-B must assign and define the mandatory recovery-material nested class
```

Therefore the sequencing rule is:

```text
2c-A
    -> freezes outer canonical settlement structure

2c-B
    -> closes mandatory recovery material
    -> makes complete market Canon(B) constructible
    -> makes final conformant market b constructible

ONLY THEN
    -> encoder work may begin
```

This is the exact boundary. 2c-A is not permitted to claim more.
