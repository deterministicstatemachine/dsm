# Device identity presentation — required semantics

Scoping document. It states the properties a device-identity presentation path must have. It is
**not a design**: it names no object, no field, no wire schema, no endpoint, no resolver
implementation, and no mechanism for authenticating Device Tree root progression. Those are gated
below, deliberately.

## Why this is scoped before it is designed

[Area 8 of the Rev 15 conformance delta](../reports/2026-08-21-rev15-conformance-delta.md) records
that a foreign verifier cannot construct a chain from a vault it discovers to an authenticated
owner-device authority, and that three edges are broken independently.
[The authority audit](../audits/2026-08-22-owner-device-identity-authority.md) then asked whether
any existing genesis-authenticated authority can authorize Device Tree root progression, and found
none: under the canonical Genesis v2 profile there is no genesis-committed public key for such a
mechanism to be rooted in.

Designing the presentation object before that is settled would fix the wrong shape. The object's
contents, its publication form and its verification order all depend on what the `g_o → R_G` edge
turns out to be — whether the root is authenticated by a genesis-time commitment, by a succession
chain, or by something introduced for the purpose. A schema frozen now would encode an assumption
about an answer nobody has.

There is also a specific failure this ordering avoids. The natural shortcut — sign `R_G` with a
device key — is circular whenever that key's standing is itself established by membership in `R_G`.
Circularity of that kind does not announce itself in a passing test; it produces a verifier that
accepts, for reasons that do not hold.

## The required property

A foreign verifier, holding `g_o` and nothing else it has not independently authenticated, must be
able to discharge this chain in order:

1. **Root resolution and authentication.** Obtain the current or applicable Device Tree root for
   `g_o`, and authenticate it against an authority whose own legitimacy does not derive from that
   root. *(Blocked: this is the audit's open question.)*
2. **Membership.** Verify an inclusion proof for `d_o` under exactly the root authenticated in
   step 1 — not a root supplied alongside the proof, and not a root read from a second fetch.
3. **Identifier recomputation.** Recompute `d_o = H("DSM/devid" ‖ AK_pk ‖ AttA)` from
   independently presented `AK_pk` and `AttA`, and require equality with the leaf proven in step 2.
4. **Promotion.** Only then treat `AK_pk` as owner authority for facts attributed to `d_o` under
   `g_o`.

Each step must be discharged against material the verifier authenticated, not against material a
provider asserted. **Repairing a proper subset leaves the chain broken**: publishing `AttA`, for
instance, closes step 3 and nothing else — a `d_o` self-consistent with a presented `AttA` is not
yet a `d_o` this genesis authorized, since anyone can generate a keypair and a 32-byte value whose
hash is self-consistent.

## Standing rules the design must respect

**Discovery is not authority.** Mutable paths, quorum-agreed mirrors and content-addressed
directories may *locate* candidate material. They never authenticate it. Agreement among mirrors is
a property of a record; it is not a statement about a key. This is the same rule area 4 enforces
for object identity, applied one level up to authority — and it is the rule the current device
registry violates by being consumed as though it established `d_o → AK_pk`.

**Publication must be immutable, addressed by content.** Inherited from area 4: a consumer must be
able to re-derive the canonical address of what it fetched and compare before decoding. A `/latest`
pointer may index; it may not identify. Whatever object carries the presentation is subject to this
from the start rather than migrated into it later.

**Verification order is normative, not an implementation detail.** A verifier that recomputes `d_o`
before authenticating the root it will check membership against has proven nothing about
authorization, even though every individual operation succeeded. The order above is part of the
requirement.

**No relative-only authentication at a foreign boundary.** DSM's existing chains — per-step EK
certificates, recovery authority, Kyber identity binding — are sound and all terminate at an
`AK_pk` pinned earlier in a bilateral relationship. That is adequate between counterparties that
pinned each other. It is not adequate for a verifier meeting a counterparty it never pinned, which
is exactly the case this path exists to serve.

**Fail closed, and fail legibly.** An unresolvable identity is a refusal, never a downgrade to an
unauthenticated key. The refusal must distinguish "no presentation published" from "presentation
present and invalid" — the first is a liveness condition, the second is an attack or a bug, and a
single error conflating them would hide the one that matters.

## What stays paused

The five `compose_vault_state` call sites are the resumption surface:

- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/dlv_routes.rs:1812,2067,2493,4894`
- `dsm_client/deterministic_state_machine/dsm_sdk/src/handlers/route_routes.rs:856`

They stay as they are. `baseline.owner_public_key`, routing-advertisement keys and
identity-endpoint keys **must not** be threaded through as a temporary key source. A shim of that
kind does not fail visibly: it makes an unauthenticated key indistinguishable from a resolved one
at every site downstream, and each of those sites then silently encodes the assumption that
identity resolution already happened. The composition boundary is where the resolved authority will
eventually enter; leaving it empty keeps that fact checkable.

The key-continuity check already in `compose_vault_state` — the seq-0 birth anchor must verify and
carry the same `owner_public_key` and `storage_set_id` as the baseline
(`dsm_sdk/src/sdk/vault_state_composition.rs:367-386`) — stays. It is a real check. It is not owner
authority, and the design must not be built as though it were.

## Gate

The following are defined **only after** the `g_o → R_G` edge is specified:

- the presentation object and its contents;
- its resolver and the resolution path;
- its immutable publication form and canonical address derivation;
- any wire schema or proto message;
- the resumption of the five composition call sites.

Step 1 of the required chain is the gate. Everything else in this document is stable regardless of
how that step is answered, which is why it can be written now.

**Gate status: answered.**
[`docs/plans/2026-08-22-genesis-root-authority-and-device-tree-progression.md`](./2026-08-22-genesis-root-authority-and-device-tree-progression.md)
supplies step 1 — a dedicated Genesis Root Key derived from `wallet_seed` without folding `G`, and
committed inside a Genesis v3 `G` preimage, so a verifier authenticates it by recomputation alone.
Root progression is authorized by a GRK-signed delegation naming a device key directly, never by
tree membership. That document restates the required chain above as an ordered acceptance predicate
(P0–P6) and carries the same order-normativity rule. The items listed under this gate remain
undefined and are now gated on **that** document being accepted as normative.

## Sequencing note

This work does not block the Rev 15 items already unblocked — the `q` rule, Anchor V2's encoder,
and area 4's immutable namespace all proceed independently. It sits above the byte-encoding layer:
`CCB(V_n)` can be completed once its fifteen members and their encodings are fixed. What cannot be
completed until this lands is foreign verification of the authority and provenance of `g_o`, `d_o`
and `r_o` — and therefore the end-to-end trader-side market path, whose blocked edge is
foreign-vault composition and parent authentication.
