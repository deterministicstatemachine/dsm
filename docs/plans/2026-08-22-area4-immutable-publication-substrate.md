# Area 4 — the immutable publication substrate

Normative design for the generic substrate only: content-addressed immutable objects, and
discovery indexes that are explicitly not authoritative. **No settlement economics, no identity
semantics, no Device Tree rules inside the storage node.**

Baseline `a05e6981`. Prerequisite for publishing the substrate classes `0x0018`–`0x001A` of
[the CCB registry](../papers/ccb-object-registry.md), and for anything that later resolves them.

## Scope

**In.** `PutImmutable` / `GetImmutable` by canonical bytes, the exact content-address derivation,
hash enforcement on write *and* read, `IndexAdd` / `IndexResolve` as discovery-only, no-overwrite
semantics, and the client-side rule that selects chain objects by authenticating them.

**Out, deliberately.** `ReadBinding` and `CompareExchangeMany` — those are the conditional-binding
register of areas 1 and 2, a different object with different atomicity requirements. The
owner-authenticated SoFi authority-position commitment is also out: it should bind a canonical
transition *position*, and it is designed after this substrate is fixed rather than against an
interim one.

## What Rev 15 requires

§15.3 (spec:1561-1563) defines, for an immutable payload `P` in namespace `N`:

```
addr(P) = H(DSM/storage-object ‖ N ‖ H(N ‖ P))
```

Req 15.2 (spec:1564-1566): `PutImmutable(P)` is idempotent for identical bytes, must not overwrite
a different payload at the same canonical address, and **a hash/address mismatch is a storage
error**. Req 15.3 (spec:1567): every Class K consumer must re-hash returned bytes and compare
against the *requested* address **before decoding or verifying higher-level content**.

§15.4 (spec:1570-1578) makes a discovery index a map `path → {addr₁,…,addrⱼ}`. Req 15.4: index
mutation may add, remove or advance pointers, but must not mutate the objects. Req 15.5 is the one
that matters most:

> A protocol validity rule must never say "the bytes currently under logical path `p` are
> authoritative." It must say "resolve `p` to one or more content addresses, fetch the immutable
> bytes, and verify them."

§15.2 item 7 forbids a member from treating a mutable discovery path as canonical object identity.

## Current state — four divergences

The conformance report records two. Preparing this design surfaced two more, and the second is the
one that would break the new substrate classes.

**1. The store enforces no immutability.** `upsert_object` is
`ON CONFLICT (key) DO UPDATE SET value = excluded.value, …`
(`dsm_storage_node/src/db/sqlite.rs:1034-1036`). Last writer wins, for every object key.

**2. Mutable paths are treated as identity.** `sofi/vault-state/{vault}/latest`
(`sdk/vault_state_anchor_codec.rs:78-81`) and `sofi/vault-state-inclusion/{vault}/latest`
(`sdk/vault_smt_inclusion_codec.rs:38-41`) are published and consumed as authoritative and
overwritten in place.

**3. The shipping content address binds a mutable logical path.**

```rust
addr := H("DSM/object\0" ‖ dlv_id ‖ path ‖ H("DSM/obj-bytes\0" ‖ content))
```

(`dsm_storage_node/src/api/objects/store.rs:90-101`). Three problems, and they compound. The
address is **not** a function of the content alone, so identical bytes at two paths have two
addresses and `PutImmutable` cannot be idempotent in the sense Req 15.2 means. It binds `path`,
which is precisely the mutable-discovery-path-as-identity confusion of §15.2 item 7 — the address
*is* the identity, so binding a path into it makes the path load-bearing. And the namespace is
`dlv_id ‖ path` rather than a declared namespace, with the inner hash under an unrelated tag
(`DSM/obj-bytes`) instead of `N`.

**4. The generic object store parses payloads, and does it by sniffing.** `put_object` calls
`authenticate_vaultpost_smart_policy_if_present` (`store.rs:162`), which decodes the body as
`VaultPostProto`, then decodes `vault_data` as `LimboVaultProto`, then inspects the fulfillment
condition and validates embedded `SmartPolicy` bytes
(`dsm_storage_node/src/api/identity/authenticate.rs:86-112`).

This is application semantics inside the generic store, but the sniffing is the sharper defect:
acceptance depends on whether the bytes *happen* to decode as one particular proto. Protobuf is
permissive, so this is not a contrived risk — **a `DeviceTreeRootTransition` CCB blob that
coincidentally parses as a `VaultPostProto` would be refused by the store**, and the failure would
look like a storage error rather than a schema collision. A generic substrate cannot have
content-dependent acceptance.

**Already well-shaped, do not regress.** The client's `frozen_publication_artifact` table is keyed
`(object_key, content_digest)` and supersedes rather than overwrites
(`storage/client_db/frozen_publication_artifact.rs:31-35,161-166`), with the digest derived from
the bytes and "no API that accepts a caller-supplied digest" (`:103`). The gap is the node contract
and the consumer's re-hash, not the client's bookkeeping.

## The address derivation

Namespace `N` is the object class's declared identity domain in the CCB registry — the same tag its
identity digest already uses. Written with the registry's pinned `H_dom` (§2.9,
`H_dom(d, x) = BLAKE3(d ‖ 0x00 ‖ x)`):

```
id(o)   = H_dom(N, CCB(o))                        # the object's identity, already defined
addr(o) = H_dom(DSM/storage-object, N_bytes ‖ id(o))
```

`N_bytes` is the namespace tag's ASCII spelling without a trailing NUL. It is variable-length but
followed by a fixed 32-byte digest, so the concatenation is unambiguous — the only reason no length
prefix is required here.

Four properties, each load-bearing.

**The address is a pure function of `(N, CCB bytes)`.** No path, no partition id, no writer
identity, no clock. Two independent publishers of identical bytes compute the identical address,
which is exactly what makes Req 15.2's idempotence meaningful rather than accidental.

**Class and schema version are committed transitively.** The CCB envelope is
`u16 class ‖ u16 version ‖ fields` (registry §2.1), so `id(o)` already binds both. The address must
**not** restate them — that would be the aliasing failure the registry rejects elsewhere, and two
copies of one fact in one preimage can disagree.

**One namespace per object class, declared in the registry.** Not chosen per call site.

**The node cannot check the namespace, and must not try.** Verifying that `N` matches the class
inside `CCB(o)` requires decoding the payload, which is the thing the node must never do. The
enforcement therefore splits: the node checks the *arithmetic* (address correctness), the consumer
checks the *agreement* (that the class it decoded declares the namespace it queried under). A
publisher who addresses bytes under the wrong namespace produces an object nobody resolving
correctly will find, and any consumer that does fetch it refuses at the agreement check.

## PutImmutable

Input is `(namespace, payload)` and, optionally, the address the caller expects.

- The node computes `addr` from the input by the derivation above. It never accepts a
  caller-supplied address as the storage key.
- **If the caller supplied an expected address and it differs, that is a storage error** — Req
  15.2's mismatch rule, and the check that catches a caller whose encoder disagrees with the
  registry.
- If `addr` is absent, store `(addr → namespace, payload)`.
- If `addr` is present, the stored bytes must equal the submitted bytes; return success without
  writing. This is idempotence.
- If `addr` is present and the stored bytes differ, refuse and surface it as corruption. By
  construction this is unreachable without a hash collision or a damaged store, which is why it is
  worth detecting rather than assuming away.

There is no update path and no overwrite path. Not "an update path that refuses" — no such code.

## GetImmutable

Input is an address. The node recomputes `addr` from the stored `(namespace, payload)` before
returning and **refuses to serve on mismatch**. That is hash-on-read: it detects a corrupted or
tampered row at the node rather than shipping it and hoping the consumer notices.

The consumer re-hashes anyway. Req 15.3 is not satisfied by the node's check — the node may be
hostile, and a check performed by the party you are verifying is not a check. Node-side rehash is
defence in depth against corruption; consumer-side rehash is the actual security boundary.

## Discovery indexes

`IndexAdd(path, addr)` and `IndexResolve(path) → {addr…}`. An index stores **addresses only, never
bytes**, and no rule anywhere may depend on which address an index returns first, most recently, or
at all.

Index writes sit behind the same device authentication as object writes
(`dsm_storage_node/src/main.rs:216-220`), so entries are attributable and rate-limited. The
protocol never depends on *who* added an entry.

`IndexResolve` is bounded and paginated, and consumers bound how many candidates they fetch. A
spammed index raises a consumer's cost; it cannot suppress a real object, because the real
addresses remain resolvable and junk fails authentication and is discarded.

**This is what removes the Device Tree denial of service.** Today one anonymous
`PUT /devtree/root` at `i64::MAX` locks a genesis's slot indefinitely, because a mutable slot
ordered by a client-supplied version has exactly one occupant
(`dsm_storage_node/src/db/sqlite.rs:613-619`). Under this substrate a garbage publication is an
unreferenced immutable object and, at worst, one junk index entry. There is no slot to squat.

## Consumer rules

A Class K consumer, in order:

1. Resolve `path → {addr…}`. Treat the result as a hint set, complete or not.
2. Fetch bytes for a candidate address.
3. **Re-hash and compare against the requested address, before decoding anything.**
4. Decode, and verify the object class declares the namespace the address was computed under.
5. Apply the object's own protocol rules.

For chain objects — delegations and transitions — the consumer **selects by authenticating, never
by asking the index which is latest**. It folds candidates into a chain under the acceptance
predicate of [the area 8 semantics](./2026-08-22-genesis-root-authority-and-device-tree-progression.md)
and takes the authenticated tip. An index that omits the real tip yields a shorter authenticated
chain, which is withholding — visible as such, and bounded by that document's position-scoped
result rather than papered over with a "latest" the node asserts.

No validity rule may be phrased as "the bytes currently at `p`". Every rule resolves, fetches,
re-hashes, then verifies.

## What the node must never do

- decode a payload, or vary acceptance by what the payload happens to parse as;
- order objects by a client-supplied version, sequence or timestamp;
- treat a logical path as an object identity;
- decide protocol validity, quorum, or economic outcome.

Deletion is a storage-capacity concern, not a protocol one. An object may be garbage-collected under
node policy, but deletion must never be implemented as overwrite, and **no validity rule may depend
on absence** — a deleted object and a withheld one are indistinguishable to a verifier.

## Clean cut

No dual-read, per the beta rule. The path-bound address derivation and `upsert_object` are removed
rather than deprecated; the `/latest` mirrors become indexes; the Device Tree root slot becomes
transition objects plus an index. Schema bump and reprovision. The payload-sniffing call is deleted
outright — not gated behind a flag, since a flag would leave content-dependent acceptance reachable.

**Two shipping tests assert the divergence and must be inverted, not deleted quietly.**
`compute_object_address_differs_by_path` (`store.rs:451`) and
`compute_object_address_differs_by_dlv` (`:467`) currently pass *because* the address binds a path
and a partition id. Under this design the first must invert — identical bytes, different paths, same
address — and the second loses its subject entirely, since no partition id enters the derivation.
A cut that leaves them green has not landed. They are named here because a test asserting the old
property is the most likely place for the old property to survive a rewrite.

## Proof obligations

1. **Address is path-independent.** Identical bytes published under two different logical paths
   produce the identical address, and the second put is idempotent.
2. **Idempotence.** Two puts of identical `(N, payload)` leave exactly one stored object and both
   return the same address.
3. **Expected-address mismatch is an error.** A caller supplying an address that disagrees with the
   computed one is refused rather than silently corrected.
4. **No overwrite path exists.** Statically: no update statement on the object table. Behaviourally:
   corrupt a stored row and confirm `GetImmutable` refuses rather than serving it.
5. **Consumer re-hash is mandatory and is the boundary.** A node returning bytes that do not hash to
   the requested address must be refused by the consumer *even if the node claims success*.
6. **Namespace/class agreement.** An object addressed under a namespace its class does not declare
   is refused at the consumer, after re-hash and before use.
7. **Blindness restored.** A CCB blob crafted to also decode as `VaultPostProto` is stored and
   returned unchanged. This is the mutation control for divergence 4 — it must fail before the fix
   and pass after, or the fix was not demonstrated.
8. **Index spam degrades, never suppresses.** With junk addresses added to a chain's path, the
   consumer still authenticates the real chain and reaches the same tip.
9. **No rule keyed on absence.** Removing an index entry changes what a consumer discovers, never
   whether an object it already holds is valid.
10. **Mutation controls.** Each gate above disabled in turn must turn its test red.

## What this unblocks, and what it does not

Landing this gives the substrate classes `0x0018`–`0x001A` a publication model with stable identity,
which is the precondition the area 8 design named. It does **not** deliver a frontier: an
authenticated chain still proves descent rather than currency, and no index makes it otherwise —
an index that returns the true tip is indistinguishable from one that returns a truthful prefix.

Next after this, and only after: the owner-authenticated SoFi authority-position commitment, which
binds an exact authenticated `DeviceTreeRootTransition` position now that such a position has both
stable bytes and a stable immutable identity.
