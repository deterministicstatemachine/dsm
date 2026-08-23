# The SoFi authority-position commitment

Answers the question area 8 left as the second precondition on the five `compose_vault_state` call
sites: **which owner-authenticated artifact commits the exact `DeviceTreeRootTransition` position
against which the vault owner's `AK_pk` is verified?**

Baseline `44fbfb9d`. Depends on the area 8 semantics, the CCB substrate classes, and the
[Area 4 immutable substrate](./2026-08-22-area4-immutable-publication-substrate.md).

## Decision

The position lives in the owner-committed vault state, as `VaultStateV2` **schema 2** field 13:

```
owner_authority_transition_digest = t_j = H_dom(DSM/devtree-transition, CCB(T_j))
```

naming the exact `DeviceTreeRootTransition` under which the owner asserts the device authority that
signs for this vault.

### Why the state, and why a new schema version

**Why the state.** The position is authenticated by exactly the mechanism that authenticates every
other vault fact: it is inside `CCB(V_n)`, therefore inside `c_n = H_dom(DSM/vault-state,
CCB(V_n))`. No new signature and no new authority path. A separate position object was the
alternative and is worse — its freshness *relative to a vault generation* would be an unbound
question, and the trader would have to decide which position applies to which state. Inside the
state, a generation and its authority position cannot disagree, because they are one commitment.

**Why schema 2 and not a redefinition of schema 1.** Registry §2.8 is explicit: once an
`(object_class, schema_version)` pair ships, changed semantics require a **new schema version**.
Schema 1 field 13 is `owner_root`, "the authenticated owner root" — Rev 15's undefined phrase.
Giving those same bytes a precise new meaning under the same schema version is exactly the
prohibited move.

That the field is **live but unset in production** — encoded at `dsm/src/ccb/state.rs:240,276`, and
set by nothing outside the `[0xA3; 32]` fixtures at `dlv/vault_state_anchor_v2.rs:483` and
`tests/ccb_conformance.rs:335` — is useful deployment information. It means the cut is cheap. It
does not repeal the registry rule, and an earlier revision of this design treated it as if it did.

**Schema 1 is burned, not kept.** Its number is recorded so it is never re-assigned; nothing in
production decodes it. Schema 2 renames the field, because a transition digest is not a "root" and
calling it one was inherited imprecision from a phrase the specification never defined.

## AnchorV3, not a mutated V2

`VaultStateAnchorV2` is **removed from the active protocol**, not amended and not preserved as a
historical primitive. Two earlier revisions of this design got this wrong in opposite directions:
the first proposed mutating its preimage in place, which would have broken the pin that preimage
exists to hold (`dlv/vault_state_anchor_v2.rs:286`); the second proposed keeping it alive as a
legacy artifact, which is coexistence. Both are withdrawn. The `/v2` domain is burned and never
reused, and its pinning test is deleted with the artifact it pinned rather than amended to track a
live format.

**AnchorV3 is the only anchor/baseline form.** Its authoritative payload is the current state
commitment and nothing else:

```
signed_payload = H_dom(DSM/vault-state-anchor/v3, c_n)
```

**No object class is required for it.** Its authoritative content is one fixed-width digest, so
there is no field layout to declare and no ambiguity to resolve — the preimage is the tag, the
separator and 32 bytes.

Convenience metadata (generation, reserves, storage set) may travel beside it in transport, but is
**never a second source of truth**: a consumer re-derives every such value from `V_n` and refuses on
disagreement rather than preferring either copy.

## The state/route identity cut

Not an amendment bolted onto the existing model, and not a coexistence plan. **`c_n` becomes the one
identity of a DLV state, everywhere it is referenced**, and what it replaces is deleted.

```
V_n canonical identity        c_n = H_dom(DSM/vault-state, CCB(V_n))
Allocation.parent_binding     c_n
settlement resource key       k_v = H_dom(DSM/binding-keyset, c_n)
SettlementBundle parent refs   c_n
RouteCommitmentBody            carries no current-encumbrance commitments
```

### What is being replaced, stated normatively

The normative predecessor is **`p_v`, a single digest** — Def 9.1 gives `Allocation` a
`parent_binding`, §9.3 makes it `p_v`, and the registry declares exactly that
(`0x0015` schema 1, field 2). An earlier revision of this document pointed instead at
`RouteCommitHopV1`'s `(anchor_seq, reserves_digest, anchor_digest)` triple and called it "route
parent identity today". That triple is the **shipping implementation representation** and a deletion
target; it is not the thing the specification says a route binds, and using it as the predecessor
put the argument on the wrong footing.

**The reason for the replacement is projection, not duplication.** `p_v` commits `vault_id`,
`generation`, the predecessor edge `h_n`, the reserves digest, `S` and `q` — a *selected projection*
of `V_n`. `c_n` commits the **exact complete current state**. A parent identity that omits parts of
the parent cannot detect changes in the parts it omits, and the omitted part that matters most here
is the one the position work introduced: the authority position itself.

### `c_n` absorbs `vault_id`, so the copies go too

`c_n` commits `vault_id`, because `vault_id` is a field of `V_n`. Every place that supplies both is
therefore an encodable pair that can disagree — one naming a vault, the other naming a state
belonging to a different one. Two such copies remained after the first pass and are removed:

- **`k_v = H_dom(DSM/binding-keyset, c_n)`.** The domain tag already says the key names a binding
  resource; `c_n` already says which DLV parent state. Restating `vault_id` adds no safety.
- **`Allocation` drops `vault_id`** — `(c_n, Δ_in, Δ_out, e, Φ)`. A verifier resolves `V_n` from
  `c_n` and reads the authoritative identifier there.

**The `AllocationBundle` knock-on is real and is taken, not worked around.** `0x0016` schema 1
ordered its set by element CCB and justified that as ordering by vault id, which held only because
`vault_id` was field 1 of the element. With `vault_id` gone that argument disappears, so `0x0016`
becomes schema 2 canonicalized by complete Allocation CCB, with schema 1 burned. Distinct-DLV is
checked against the identifiers recovered from the bound `V_n` states. Keeping a duplicate
identifier purely to preserve a sorting explanation would be exactly the alias being removed.

### The knock-on: `{EC_v}` goes

Rev 15 §9.3 carries `{EC_v}` in `Q`, and the registry says plainly why: it "is not implied by `p_v`,
which commits the parent state commitment `h_n` and the current generation's reserves digest, but
not the current generation's encumbrance set."

**That justification is conditional on `p_v` and does not survive `c_n`.** `E` is a field of `V_n`,
so `c_n` commits the current encumbrance set already. Keeping `{EC_v}` beside it would commit one
fact twice in one object, in two independently encodable values free to disagree — the alias class
removed from `B_M`, from the transition object, and now from the parent binding. It would survive by
inertia rather than by argument.

**`Allocation.e` stays.** It is not an alias: `c_n` *authenticates the parent's entire encumbrance
state*, `e` *selects the one claim this allocation consumes*. Authentication and selection are
different jobs, and no parent commitment tells a verifier which claim a leg is spending.

### The cut, with no legacy anywhere

Schema and domain numbers are recorded as **burned** so they are never re-assigned. That is the only
thing carried forward — it prevents accidental reuse and is not compatibility support. **No
production path decodes, accepts, emits, routes, composes or falls back to any retired form.**

| Retired | Replacement |
|---|---|
| `VaultStateV2 0x0001` schema 1 | schema 2 only; field 13 is `owner_authority_transition_digest` |
| `StorageSet 0x0002` schema 1 | schema 2 only — the frozen `storage_set_id` layout becomes an ordinary CCB object |
| `EncumbranceClaim/Set 0x0004`, `0x0005` schema 1 | schema 2 only; claim parent is `c_n`, no `vault_id`; `EC_v` deleted |
| `VaultStateAnchorV2` and Def 6.4 | **removed from the active protocol** — AnchorV3 is the only anchor/baseline form; the `/v2` domain is burned |
| `Allocation 0x0015` schema 1 (`p_v`) | schema 2 only, `parent_binding = c_n` |
| `RouteCommitmentBody 0x0017` schema 1 | schema 2 only, no `{EC_v}` |
| `0x0016` schema 1 | schema 2 only, ordered by complete Allocation CCB |
| `RouteCommitHopV1` triple | deleted, not adapted — the hop carries `c_n` |
| resource keys on `h_n` | `k_v = H_dom(DSM/binding-keyset, c_n)` |

**AnchorV2 is not preserved as a "historical primitive".** An earlier revision proposed keeping it
that way; that was still coexistence, and it is withdrawn. It is removed from the protocol, and its
pinning test goes with the artifact it pinned rather than being amended to track a live format.

Storage, database and proto state take a **clean schema cut and reprovision**: no migrations, no
compatibility columns, no `if old_version` branches, no fallback parsing. There is nothing to
migrate *from*, because no old-format state remains valid.

### Normative amendment surface

One coherent change, not a scatter of edits: **Def 4.1** (`r_o` gains its concrete meaning),
**Def 6.4** (deleted, with the V2 anchor and its domain), **Req 6.6** (restated as the state-identity
cut), **Def 6.17** (`k_v`), **Def 9.1** and **Def 9.2** (`Allocation`, bundle canonicalization),
**§9.3** (`X` loses `{EC_v}`), **§8** (the claim parent `p` pinned to `c_n`), the `SettlementBundle`
DLV-parent fields and the stale-parent checks. All resolve to **the same exact current-state
identity**, which is what makes this a cut rather than a set of amendments.

**§8 matters more than its size suggests.** The `e_j` preimage carried a vault parent `p`; leaving
`p` ambiguous after deleting `p_v` would preserve the old parent model through the encumbrance path,
where nobody would look for it. It is pinned to `c_n`, and the claim's own `vault_id` goes with it.

**Four further sites closed in the same sweep**, each the old model surviving somewhere quieter:

- **Def 6.14 `T_v`** carried the vault identifier, parent generation, parent state commitment and
  parent reserves digest — the `p_v` projection under another name. The parent side of `T_v` is now
  exactly `c_n`; everything else is read from the authenticated state.
- **Def 5.2 `M`** committed `vault_id` beside `c_0` — the same `(vault_id, c_n)` alias one
  generation earlier. Dropped.
- **`TradeDigest`** carried participating vault identifiers beside parent bindings. Once those are
  `c_n`, the identifiers are redundant. Dropped.
- **`EC_v` itself** was still *defined* in §8 while §9.3 deleted its only consumer. A derived
  commitment with no consumer is an alias waiting to be re-adopted, so it is deleted and its symbol
  burned.

**Def 6.4a defines AnchorV3 normatively.** An earlier revision declared it only in this plan while
the specification deleted the sole anchor it defined — leaving the replacement living in a document
with no normative force. The `/v3` domain is now reserved in the domain table and the owner-signed
baseline over `c_n` is defined in the specification itself.

**The `StorageSet` freeze is gone.** `0x0002` schema 1 was the registry's largest explicit legacy
encoding, kept because "every deployed vault's signed anchor already commits a `storage_set_id`
under this construction". The cut deletes those anchors, so the rationale is void. The registry's
"absorb as shipped" tier goes with it: it had exactly one member and, under a no-legacy rule, no way
to acquire another.

**These amendments are made in this change**, in `.github/instructions/sofispecs.instructions.md`.
The no-legacy rule is why: a registry declaring `c_n` while the specification still declares `p_v`
is precisely the temporary disagreement a clean cut forbids, and the specification would win in any
implementation that read it.

## The position is invariant across market successors

**A market successor copies `owner_authority_transition_digest` byte-for-byte.** Not
"non-decreasing", not "a descendant is allowed" — identical.

An earlier revision required only that the position be non-decreasing along the vault's generation
chain. That is unsound for the specific reason this whole area exists. A market successor executes
**while the owner is absent**; a rule permitting a descendant would let the live trader advance the
owner-authority reference with no fresh owner authority behind it. The trader would be choosing
which authority position the owner is bound by.

Owner catch-up does not alter it either: catch-up records already-realized DLV history, it does not
create a new DLV authorization, so it has nothing new to authorize with.

Changing the position for an active vault therefore requires an **explicit owner-authorized
successor family**, deliberately not defined here. Beta has no authority rollover for a live vault.

## Owner absence, and why this stays compatible with it

**A conforming verifier cannot require an owner-signed anchor at the current generation.** The
entire reason DLV market execution continues without fresh LP participation is that the owner may be
offline while market successors advance the vault. A design that demanded a fresh owner signature at
generation `n` would delete that property.

The shape that preserves it:

- the **last owner-authenticated baseline** establishes the authority position;
- **market successors preserve it exactly**, per the invariance rule above;
- the **current `c_n`** is authenticated by folding the realized DLV successor history forward from
  that baseline — which is what composition already does for reserves and sequence.

So the trader needs an owner-authenticated state at some generation `m ≤ n`, plus an authenticated
successor chain from `m` to `n`. The authority position it verifies against is the baseline's, and
invariance is what makes that the same value the current state carries.

## Verification staging

The staging matters as much as the fields, and an earlier revision got it circular: it said the
composer begins "having verified an anchor as it does today," then promoted the key at the end. But
`verify_vault_state_anchor_v2` **requires** `expected_owner_public_key`, and its own contract says
that key "must come from material the caller has already authenticated"
(`dlv/vault_state_anchor_v2.rs:176-186`) — naming "the composed `V_n`" as such a source. At a
foreign vault the composer does not have that key. That is the gap this design closes, so it cannot
be assumed at step one.

The correct order, with the key held as a **candidate** throughout:

1. **Cryptographic check only.** Verify the signature under the *presented candidate key*, and
   retain **the exact key bytes used**, call them `K_cand`. This establishes "this key signed these
   bytes" and **nothing about whose key it is** — the weakness the V2 doc comment names about
   embedded keys.
2. **Integrity-bind the candidate to the state.** The signed payload is `c_n`, so a valid signature
   binds *`K_cand`* to *that state commitment*. Still no authority.
3. **Fetch and re-hash `V_n`.** Resolve `CCB(V_n)` on the Area 4 substrate; require
   `H_dom(DSM/vault-state, CCB(V_n)) = c_n` before decoding.
4. **Read the bound facts** — `g_o`, `d_o`, and `owner_authority_transition_digest`.
5. **Discharge P0–P6** of the area 8 predicate at that **bound position**: authenticate the Device
   Tree root at that exact transition, prove `d_o` included, recompute
   `d_o = H("DSM/devid" ‖ AK_pk ‖ AttA)` from independently presented material. Call the key
   proven here `K_proven`.
6. **Require `K_cand == K_proven`, byte for byte.** Only then is that key owner authority, and only
   then may the step-1 signature be reinterpreted as an owner-authenticated signature.

### The equality in step 6 is a predicate, not bookkeeping

Steps 1 and 5 each take a key as input, and **nothing in steps 2–5 forces them to be the same key.**
An implementation that keeps two variables — `K_anchor` which signed a valid `c_n`, and `K_owner`
which passes P0–P6 — can prove authority for one and then reinterpret the *other's* signature as
owner-authenticated. Both objects are individually valid; the conclusion is false.

That is an attack shape, not naming hygiene. An attacker who can present any state commitment signed
by a key it controls, alongside a genuine identity proof for the real owner's key, would have the
composer treat its own signature as the owner's. The equality is the only step that rules it out, so
it is stated as its own numbered requirement rather than folded into "promote".

**No stage before 6 may call anything "owner verified",** in code, in a variable name, or in a log
line. The failure this design exists to prevent is precisely a verifier that believes it has checked
the owner when it has checked a key.

## Publication

`CCB(V_n)` publishes as an immutable object on the Area 4 substrate, in the namespace the registry
declares for class `0x0001`. Its address is `addr(N, CCB(V_n))` and its identity is `c_n` — both
already defined, nothing new derived. It is a natural first consumer of that substrate: `V_n` for a
given `n` never changes, so there is nothing an overwrite could mean.

## Scope

**Delivered: bound verification with no freshness assumption.** *Was this `AK_pk` the owner authority
for `d_o` under `g_o` at the position this state commits?* — answerable from presented material
alone, with no frontier.

**Not delivered: revocation against a stranger.** The owner chooses the position it commits at
baseline. A holder of a retired `AK_pk` can commit a position at which that key was still authorized
and produce a self-consistent proof; a trader with no frontier cannot tell that a later position
retired it. Inherited from area 8, not introduced here. **The position commitment must not be read
as solving revocation** — and note that invariance narrows rather than widens what a live attacker
can do, since it forecloses moving the reference mid-vault.

## Landing sites

- **Registry**: class `0x0001` gains schema 2; §5.1 gains the schema-2 field table and the field's
  definition. Schema 1 is untouched.
- **AnchorV3**: a new domain and a new signed payload. `VaultStateAnchorV2`, its `parent_binding`
  helper and its pinning test at `dlv/vault_state_anchor_v2.rs:286` are **deleted**, not modified.
- **`RouteCommitHopV1`**: the `(anchor_seq, reserves_digest, anchor_digest)` triple at
  `proto/dsm_app.proto:1225-1227` is deleted; the hop carries `c_n`. Both field numbers are burned.
- **Registry**: `0x0001`, `0x0015` and `0x0017` move to schema 2, with schema 1 burned in each.
- **The five composition call sites** resume only after both preconditions hold: P6 dischargeable,
  and this commitment present.

## Proof obligations

1. **Schema separation.** A schema-1 `V_n` and a schema-2 `V_n` with identical field bytes produce
   different `c_n`, because the envelope's version differs. A decoder must never read schema-1
   field 13 as an authority position.
2. **The position is authenticated, not asserted.** A `CCB(V_n)` whose re-hash does not equal the
   signed `c_n` is refused before any field is read.
3. **Invariance across market successors.** A market successor whose
   `owner_authority_transition_digest` differs from its parent's — *including a strict descendant of
   it* — is refused. The descendant case is the one that must be tested, because it is the one the
   earlier rule would have allowed.
4. **Owner absence.** With no owner-signed artifact at generation `n`, a trader still authenticates
   `c_n` by folding realized successors from a baseline at `m < n`, and verifies at the baseline's
   position.
5. **Staging is not reorderable.** A composer that promotes the candidate key before P6 must fail a
   test that presents a valid signature over a valid `c_n` whose `d_o` does not recompute from the
   presented `AK_pk`/`AttA`. This is the mutation control for the entire area — it must fail before
   this change and pass after.
6. **Two-key confusion is refused.** A valid AnchorV3 signature under `K1` **plus** a valid P0–P6
   identity proof for a *distinct* `K2` must be refused, even though both objects are individually
   valid and neither is forged. This is the case an implementation reaches by keeping two variables,
   and it is the one a test suite built only from valid/invalid object pairs will not generate on
   its own.
7. **No second source of truth.** AnchorV3 transport metadata disagreeing with `V_n` is a refusal,
   not a preference for either value.
8. **No legacy path exists.** Statically: no decoder branches on schema 1 for `0x0001`, `0x0015` or
   `0x0017`; the `DSM/vault-state-anchor/v2` domain appears nowhere outside the burn record; the hop
   triple's field numbers are unused. Behaviourally: a schema-1 blob is refused, not upgraded.
9. **`{EC_v}` is absent and unmissed.** A route whose parent bindings are `c_n` verifies its
   encumbrance state end-to-end with no `{EC_v}` present — the test that shows the removal lost
   nothing rather than merely that the field is gone.
10. **One identity everywhere.** `Allocation.parent_binding`, `k_v`, the stale-parent check and every
    `SettlementBundle` parent reference resolve to the identical `c_n` for a given state. A test
    that computes it two ways and compares is the cheapest guard against the projection problem
    returning.
11. **No `vault_id` copy survives.** No object supplies both a `vault_id` and a `c_n`. Asserted
    structurally, because the failure is silent: a mismatched pair is perfectly encodable, and a
    verifier that trusted the carried identifier over the bound state would never notice.
12. **Bundle ordering without `vault_id`.** An `AllocationBundle` whose members are ordered by
    complete Allocation CCB is canonical, and two members whose bound `V_n` share a `vault_id` are
    refused as non-distinct DLVs — the check that replaces the removed identifier rather than
    dropping it.
13. **Mutation controls.** Each gate above disabled in turn must turn its test red.

## Sequence

**The normative cut gates this work and is not this document's to make.** Def 9.1 and §9.3, Def 6.17,
the stale-parent checks, the `SettlementBundle` parent fields, and the removal of Def 6.4 — all
resolving to `c_n`. It is one change because it is one identity.

After it lands, in order: registry schemas (`0x0001`, `0x0015`, `0x0017` to schema 2, schema 1 burned
in each), then AnchorV3 with V2 deleted, then `CCB(V_n)` publication on the Area 4 substrate, then
the composer staging above including the step-6 key equality, then the five call sites resume.

There is no migration step in that list, and that is deliberate: a clean reprovision means no old
state is valid, so there is nothing to migrate and no compatibility code to write.
