# The SoFi authority-position commitment

Answers the question area 8 left as the second precondition on the five `compose_vault_state` call
sites: **which owner-authenticated artifact commits the exact `DeviceTreeRootTransition` position
against which the vault owner's `AK_pk` is verified?**

Baseline `44fbfb9d`. Depends on the area 8 semantics, the CCB substrate classes, and the
[Area 4 immutable substrate](./2026-08-22-area4-immutable-publication-substrate.md).

## Decision

**`r_o` is the position.** Definition 4.1's `owner_root` — member 13 of `V_n`, described in Rev 15
as "the authenticated owner root" and defined nowhere — is the transition digest

```
r_o = t_j = H_dom(DSM/devtree-transition, CCB(T_j))
```

naming the exact `DeviceTreeRootTransition` under which the owner asserts its device authority.

### Why this field and not a new object

`r_o` is already **a member of the owner-committed state**, so it is authenticated by exactly the
mechanism that authenticates every other vault fact: it is inside `CCB(V_n)`, therefore inside
`c_n = H_dom(DSM/vault-state, CCB(V_n))`, therefore inside the lineage `h_{n+1} = c_n`. No new
signature, no new authority path, no new object class.

It is also **live but empty**. `VaultStateV2.owner_root` is encoded today as field 13
(`dsm/src/ccb/state.rs:240,276`) and set by nothing in production — the only occurrences are the
`[0xA3; 32]` fixtures in `dlv/vault_state_anchor_v2.rs:483` and `tests/ccb_conformance.rs:335`. So
this defines a declared slot rather than adding one, and there is no prior meaning to migrate.

A separate position object was the alternative and is worse for a specific reason: its freshness
*relative to a vault generation* would then be an unbound question, and the trader would have to
decide which position applies to which state. Putting the position inside the state makes that
binding structural — a generation and its authority position cannot disagree, because they are one
commitment.

## The visibility gap, and the amendment that closes it

Defining `r_o` is not sufficient on its own. The anchor's signed preimage (Def 6.4) binds
`parent_state_commitment = h_n = c_{n-1}` and not `c_n`
(`dsm/src/dlv/vault_state_anchor_v2.rs:118-123`). A trader quoting generation `n` therefore holds a
commitment to the **previous** state and cannot authenticate generation `n`'s `r_o` at all — `c_n`
first appears in the anchor for `n+1`, which does not exist yet.

Accepting that lag would mean verifying authority at a position one generation stale, and soundness
would then rest on the device tree not having progressed in between. That is precisely the class of
unstated assumption this workstream has been removing.

**Required amendment to Def 6.4.** The anchor binds the current state commitment alongside the
parent:

```
p_v = H_dom(DSM/vault-state-anchor/v2,
            vault_id ‖ generation ‖ parent_state_commitment ‖ state_commitment
                     ‖ reserves_digest ‖ storage_set_id ‖ q)
```

where `state_commitment = c_n`. This is a normative Rev 15 change and is stated here as a required
amendment rather than made here — the specification is the authority, and this document is a
consumer of it.

`h_n` is **not** replaced. The two commit different facts: `h_n` is the lineage edge to the previous
state, `c_n` is the identity of this one. Root recurrence taught this distinction the expensive way
in the transition object, and the same reasoning applies — a value that identifies a predecessor and
a value that identifies the present are not two spellings of one fact.

## Publication

The owner publishes `CCB(V_n)` as an immutable object under the Area 4 substrate, in the namespace
the registry declares for class `0x0001`. Its address is `addr(N, CCB(V_n))`, its identity is `c_n`,
and both are already defined — nothing new is derived.

This is the first real consumer of Area 4's generic substrate, and it is a good fit precisely
because the object is immutable by nature: `V_n` for a given `n` never changes, so there is nothing
for an overwrite to mean.

## Trader verification

The composer, having verified an anchor as it does today:

1. Read `state_commitment = c_n` from the anchor's authenticated preimage.
2. Resolve and fetch `CCB(V_n)` — by address, or by index then re-hash per Area 4's consumer rules.
3. Require `H_dom(DSM/vault-state, CCB(V_n)) = c_n`. The state is now authenticated *by the anchor
   the trader already trusts*, with no new trust root.
4. Decode `V_n` and read `g_o` (field 1), `d_o` (field 2) and `r_o` (field 13).
5. Discharge **P0–P6** of the area 8 predicate with `r_o` as the **bound position**: authenticate the
   Device Tree root at that exact transition, prove `d_o` included, recompute
   `d_o = H("DSM/devid" ‖ AK_pk ‖ AttA)` from independently presented material, and only then treat
   `AK_pk` as owner authority.
6. Only now is the anchor's signature meaningful as *the owner's* signature.

Step 6 is the point of the whole construction. Today `verify_vault_state_anchor` establishes that
*some* key signed the anchor and that the same key signed the birth anchor — key continuity, which
is real but is not authority. This supplies the missing half.

## What this delivers, and what it does not

**Delivered: bound verification with no freshness assumption.** The trader answers a closed
question — *was `AK_pk` the owner authority for `d_o` under `g_o` at the position this state
commits?* — from presented material alone. No frontier is required, and none is implied.

**Not delivered: revocation against a stranger.** The owner chooses the position it commits. A
holder of a retired `AK_pk` can commit a position at which that key was still authorized and produce
a self-consistent proof, and a trader with no frontier cannot tell that a later position retired it.
This is the same limitation area 8 records, inherited rather than introduced — `r_o` must not be
read as solving revocation.

**One cheap constraint that helps, stated for what it is.** `r_o` must be **non-decreasing along the
vault's own generation chain**: the position committed at generation `n` must be the same as, or a
descendant of, the one committed at `n-1`. The state chain is already linked by `h_n`, so a verifier
walking it can check this without new machinery. It prevents an authority position from *regressing*
along an honest vault lineage. It does not stop a party who can produce a fork of the vault state,
which is a different problem with its own protections, and it is not a substitute for the frontier.

## Consequences to land in the same change

- **Registry §5.1, field 13** currently reads "the authenticated owner root" — the specification's
  undefined phrase. It becomes the transition digest, with the domain named.
- **`vault_state_anchor_v2.rs:286-312`** is a test that "PINS THE DOMAIN AND THE FIELD ORDER TO REV
  15 DEF 6.4". It must be amended deliberately, in the same change as the preimage, and not merely
  updated until it passes — a pinning test that follows the code it pins is not pinning anything.
- **The five composition call sites** resume only after both preconditions hold: P6 dischargeable,
  and this commitment present. They are still paused until the amendment lands.

## Proof obligations

1. **`r_o` is authenticated, not asserted.** A `CCB(V_n)` whose re-hash does not equal the anchor's
   `state_commitment` is refused before any field is read.
2. **The anchor binds both commitments.** Changing `c_n` alone changes `p_v`; changing `h_n` alone
   changes `p_v`. Neither is derivable from the other.
3. **Position is bound, not current.** A trader shown a longer authenticated device-tree chain than
   the committed position still verifies at the committed position, and says so — no silent
   upgrade to the tip.
4. **Non-decreasing positions.** A vault state whose `r_o` is an ancestor of its predecessor's `r_o`
   is refused.
5. **Key continuity is not authority.** With a valid anchor signature and valid birth-anchor
   continuity but a `d_o` that does not recompute from the presented `AK_pk`/`AttA`, composition
   must refuse. This is the mutation control for the gap the whole area exists to close — it must
   fail before this change and pass after.
6. **Mutation controls.** Each gate above disabled in turn must turn its test red.

## Sequence

The amendment to Def 6.4 is the gating item and is not this document's to make. Once it lands:
registry field 13, the anchor preimage plus its pinning test, `CCB(V_n)` publication on the Area 4
substrate, then the composer's steps 1–6, then the five call sites resume.
