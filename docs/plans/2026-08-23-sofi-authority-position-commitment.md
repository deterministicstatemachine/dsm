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

**Schema 1 is not retired and not re-pointed.** It keeps its original, undefined field 13. Schema 2
renames the field, because a transition digest is not a "root" and calling it one was inherited
imprecision from a phrase the specification never defined.

## AnchorV3, not a mutated V2

`VaultStateAnchorV2`'s domain and field order are the Def 6.4 primitive, pinned deliberately —
including by a test that says so in capitals (`dlv/vault_state_anchor_v2.rs:286`). Changing that
preimage in place would break the pin it exists to hold. An earlier revision of this design proposed
exactly that; it is withdrawn.

If an owner-signed baseline artifact remains useful, it is **AnchorV3** under a new domain, and its
authoritative payload is the current state commitment and nothing else:

```
signed_payload = H_dom(DSM/vault-state-anchor/v3, c_n)
```

**No object class is required for it.** Its authoritative content is one fixed-width digest, so
there is no field layout to declare and no ambiguity to resolve — the preimage is the tag, the
separator and 32 bytes.

Convenience metadata (generation, reserves, storage set) may travel beside it in transport, but is
**never a second source of truth**: a consumer re-derives every such value from `V_n` and refuses on
disagreement rather than preferring either copy.

## The parent binding is exactly `c_n`

```
parent_binding := c_n = H_dom(DSM/vault-state, CCB(V_n))
```

Not the Def 6.4 tuple with `c_n` appended. `c_n` already commits `generation`, the reserves, `h_n`,
the authority position, `S` and `q`, because every one of them is a field of `V_n`. Appending `c_n`
to a tuple that separately restates those facts would put two authoritative copies of each in one
preimage — the alias class the Def 5.2 amendment removed, and the reason `old_root` was dropped from
the transition object.

The distinction against `h_n` is the one that matters and it survives: `h_n = c_{n-1}` is the
**predecessor edge**, `c_n` is the **identity of the present state**. Different facts, as root
recurrence taught expensively. Def 6.4 binds selected current facts plus the predecessor edge; a
route consuming `V_n` should bind `V_n`.

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

1. **Cryptographic check only.** Verify the signature under the *presented candidate key*. This
   establishes "this key signed these bytes" and **nothing about whose key it is** — the weakness
   the V2 doc comment names about embedded keys.
2. **Integrity-bind the candidate to the state.** The signed payload is `c_n`, so a valid signature
   binds *that candidate key* to *that state commitment*. Still no authority.
3. **Fetch and re-hash `V_n`.** Resolve `CCB(V_n)` on the Area 4 substrate; require
   `H_dom(DSM/vault-state, CCB(V_n)) = c_n` before decoding.
4. **Read the bound facts** — `g_o`, `d_o`, and `owner_authority_transition_digest`.
5. **Discharge P0–P6** of the area 8 predicate at that **bound position**: authenticate the Device
   Tree root at that exact transition, prove `d_o` included, recompute
   `d_o = H("DSM/devid" ‖ AK_pk ‖ AttA)` from independently presented material.
6. **Promote.** Only now is the candidate `AK_pk` owner authority, and only now may the signature
   from step 1 be reinterpreted as an owner-authenticated signature.

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
- **AnchorV3**: a new domain and a new signed payload. `VaultStateAnchorV2` and its pinning test at
  `dlv/vault_state_anchor_v2.rs:286` are **not** modified.
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
6. **No second source of truth.** AnchorV3 transport metadata disagreeing with `V_n` is a refusal,
   not a preference for either value.
7. **Mutation controls.** Each gate above disabled in turn must turn its test red.

## Sequence

Registry schema 2, then AnchorV3 and its payload, then `CCB(V_n)` publication on the Area 4
substrate, then the composer staging above, then the five call sites resume. No Def 6.4 amendment is
required — that proposal is withdrawn in favour of AnchorV3, which leaves the pinned V2 primitive
intact.
