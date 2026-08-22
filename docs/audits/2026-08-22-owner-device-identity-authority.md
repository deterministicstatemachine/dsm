# Owner-device identity authority audit — is there a non-circular `g_o → R_G` edge?

Read-only audit. It changes no code, proposes no mechanism, and defines no object. It answers one
question and stops.

Commissioned by area 8 of [`docs/reports/2026-08-21-rev15-conformance-delta.md`](../reports/2026-08-21-rev15-conformance-delta.md),
which records that a foreign verifier cannot construct the chain
`g_o → R_G → d_o ∈ R_G → d_o = H(AK_pk ‖ AttA) → AK_pk is owner authority`,
and that the third edge — authenticated progression of the Device Tree root `R_G` under a genesis
`g_o` — has no mechanism at all. Area 8 deliberately declines to invent one, because the obvious
choice is circular.

**Baseline.** Code read at `fbf1d1ba`. Every file cited is byte-identical at `d0bd5d0d`, the
implementation baseline the conformance report pins; see that report's *Reproducing the citations*
section for the check.

## The question, and the criterion

> What genesis-authenticated authority already exists that can authorize Device Tree root
> progression?

A candidate qualifies only if it satisfies all three:

1. **Reachable from `g_o` alone.** A verifier that knows only the genesis identifier must be able
   to obtain it. Anything requiring prior possession of the answer does not qualify.
2. **Cryptographically authenticated, not merely agreed.** Bytes that several mirrors return
   identically are an agreed record, not an authenticated statement. Presence, replication and
   first-writer-wins are ordering properties; none of them is a signature.
3. **Non-circular.** Its own legitimacy must not rest, directly or transitively, on `R_G` or on
   anything `R_G` establishes. Signing `R_G` with a device key whose standing is established only
   by membership in that same `R_G` proves nothing.

Criterion 3 is the whole reason this audit exists. Criteria 1 and 2 eliminate most candidates on
their own.

## Surface enumerated

Two things are enumerated exhaustively, so the negative result is bounded rather than impressionistic.

**Every genesis-keyed network object.** Across the storage node's forty-eight `/api/v2` routes,
exactly three are keyed by genesis:

| Route | Object |
|---|---|
| `PUT/GET /api/v2/identity/{genesis}/devtree/root` | `DeviceTreeStateV1` |
| `GET /api/v2/identity/{genesis}/devtree/proof` | `DeviceInclusionProofV1` (node-rebuilt) |
| `PUT/GET /api/v2/recovery/authority-anchor/{genesis}` | `RecoveryAuthorityAnchorProto` |

`/api/v2/genesis/{create,entropy}` are MPC-ceremony plumbing — a forwarder gated on
`DSM_GENESIS_UPSTREAM` and an entropy read (`dsm_storage_node/src/api/identity/genesis.rs:20-25`).
Neither publishes a genesis record, so **there is no published object addressed by `g_o` that
carries a key**.

**Every signed object that names a device.** `RecoveryAuthorityAnchorProto`,
`DeviceTreeRootUpdateV1`, `PostedPdsmtHead`, and the device registry row's `kyber_binding_sig`.

## Verdicts

| Candidate | Reachable from `g_o` | Authenticated | Non-circular | Verdict |
|---|---|---|---|---|
| Genesis v2 `G` preimage | n/a — it *is* `g_o` | commits no key | — | **No edge** |
| MPC `RootBindingRecord` | would be | would be | would be | **Unimplemented; and its genesis profile was demoted** |
| `RecoveryAuthorityAnchorProto` | yes | yes, but against a key it does not supply | **fails** | **Consumes the chain, does not supply it** |
| `DeviceTreeRootUpdateV1` | yes, by design | never verified anywhere | — | **Reserved field, no mechanism** |
| PD-SMT append-only head chain | by device, not by genesis | node verifies no signature | — | **Shape, not authority** |
| Device registry row + `kyber_binding_sig` | no — keyed by `d_o` | binds Kyber to AK only | — | **Discovery only** |
| `auth::device_auth` bearer token | no | bearer, issued by the same open registration | — | **Access control, not identity** |

## Findings

### Genesis v2 `G` commits no key

`G = H("DSM/genesis/v2" ‖ genesis_nonce ‖ network_id ‖ genesis_version)`
(`dsm/src/core/identity/genesis_v2.rs:92-103`). The constructed genesis carries the AK keypair
beside `G` but not inside it: `create_genesis_v2` sets `hash: v2.g` and puts the AK in a separate
`signing_key` field (`dsm/src/core/identity/genesis.rs:509-518`).

`genesis_nonce` and `AK_seed` do share a root — both are wallet-seed KDFs — but that is a shared
**secret** ancestry, not a publicly checkable binding. A verifier holding `g_o` cannot test
whether a presented `AK_pk` came from the same seed; testing it would require the seed. Under the
canonical mnemonic-rooted profile there is therefore **no genesis-committed public key at all**,
which is precisely why the `g_o → R_G` edge cannot be built by "sign `R_G` with the device key"
without circularity. There is no non-`R_G` fact that says which device key is the genesis's.

**Verdict: no edge.** This is the audit's central negative.

### The MPC `RootBindingRecord` is a design, not an implementation — and its ground shifted

The design exists and is coherent:
[`docs/plans/2026-04-24-hrw-scale-and-enrollment-hardening.md`](../plans/2026-04-24-hrw-scale-and-enrollment-hardening.md)
Phase 3 (tasks 3.1–3.4) defines `RootBindingRecordV1`, its endpoints, and a four-check bounded
validator on the devtree PUT that refuses a root write when no `RootBindingRecord` exists for the
same `G`. Its companion,
[`docs/plans/2026-04-24-genesis-mpc-and-device-tree.md`](../plans/2026-04-24-genesis-mpc-and-device-tree.md),
supplies the record at genesis time carrying `initiator_pk` — the root device's SPHINCS+ public key
— bound to a `G` produced by a commit-reveal ceremony across N≥3 storage nodes. That binding *would*
satisfy all three criteria: the key is reachable from `g_o`, it is authenticated by the ceremony,
and its legitimacy comes from the ceremony rather than from `R_G`.

Two facts stop it being the answer today.

**It does not exist.** `RootBindingRecord` occurs in the tree exactly twice — as prose inside the
`DeviceTreeRootUpdateV1` comment in `proto/dsm_app.proto:3729-3731`, and in the generated
TypeScript mirror of that same comment. No message, no field, no endpoint, no code.

**Its foundation was demoted.** The design is rooted in MPC genesis. Genesis v2 made the
mnemonic-rooted profile canonical and explicitly needs no storage nodes
(`dsm/src/core/identity/genesis_v2.rs:5-30`), retaining `CommitRevealMpcV1` as an optional
high-assurance path (`:44-52`). A `G` that no ceremony produced has no ceremony to bind a key. The
plan therefore **cannot be treated as a live answer that merely awaits implementation**; whether
any equivalent binding is available under the canonical profile is an open question, and it is the
question the follow-up design has to answer.

**Verdict: unimplemented, and not portable to the canonical genesis profile without new work.**

### `RecoveryAuthorityAnchorProto` consumes the missing chain

Structurally it is the closest thing in the tree to a genesis-scoped authority statement. It binds
`(genesis_id, device_id, H(K_A_pub))` under two SPHINCS+ signatures — one by the device's genesis
signing key (the AK), one by `K_A` proving possession — over a domain-separated digest with no
wall-clock and no counters (`dsm/src/recovery/authority_anchor.rs:64-74`). The store enforces
bind-once per genesis: the first valid anchor wins and is immutable, a different anchor for the
same genesis is refused with 409, and storage verifies no signature itself
(`dsm_storage_node/src/api/identity/recovery_anchor.rs:9-21`).

It fails criterion 3, and the module says why in its own words: the device signature is verified
"against the genesis-authenticated device pubkey fetched via the device-tree quorum path"
(`authority_anchor.rs:19-23`). Verifying the anchor therefore **presupposes an authentic `AK_pk`**
— the thing the chain was trying to establish. It consumes the chain rather than supplying it.

One qualification, stated because it is easy to overclaim in the other direction. Presenting
`AttA` alongside `AK_pk` would let a verifier test `d_o = H(AK_pk ‖ AttA)` and then check the
anchor's device signature under that `AK_pk`, at which point the anchor would genuinely bind
`g_o ↔ d_o`. But that **repairs only the first broken edge**. The verifier would still need an
authenticated `g_o → R_G` edge and a valid inclusion proof for that `d_o` before the anchor
established anything about *the current device set* — and a `d_o` self-consistent with a presented
`AttA` is not yet a `d_o` this genesis authorized. Anyone can generate a keypair and a 32-byte
value whose hash is self-consistent.

**Verdict: candidate material; not an edge today, and not made into one by `AttA` alone.**

### `DeviceTreeRootUpdateV1` is a reserved field

The proto carries `old_root`, `new_root`, `version_number` and a SPHINCS+ `signature` over
`domain_hash("DSM/dev-tree-root-update/v1", old_root ‖ new_root ‖ version_number_le)` by "the
root-binding key" (`proto/dsm_app.proto:3722-3737`). The comment states plainly that verification
is out of scope pending `RootBindingRecord`, and the Phase B audit records the same deferral twice
over ([`docs/audits/2026-05-phase-b-device-tree.md`](./2026-05-phase-b-device-tree.md) lines 80,
148, 165-166).

The message is constructed only in `dsm/tests/device_tree_root_lifecycle_test.rs`. The live
`PUT /devtree/root` handler does not accept it — it accepts a bare `DeviceTreeStateV1` and runs a
bounded validator that explicitly does not verify signatures
(`dsm_storage_node/src/api/identity/devtree.rs:16-17,206-295`). There is no signer, no
verification path, and no key the signature would be checked against.

**Verdict: the field names an authority that was never given a source.**

### The PD-SMT head chain enforces shape, not authority

`PUT /api/v2/tips/{device}/head-chain` is append-only and link-checked: the first head must be
genesis-position with an all-zero parent, a later head must be `tip + 1` with
`parent_head_hash == tip.head_hash`, no overwrite and no fork. The node decodes the head to derive
`head_hash` itself "so a client cannot lie about chain links" — but it "does **not** verify the
head signature (it lacks `K_A_pub`)" and the endpoint is public and rate-limited
(`dsm_storage_node/src/api/identity/pdsmt_head.rs:3-19`).

It is keyed by device, not by genesis, so it also fails criterion 1: a verifier holding only `g_o`
does not know which device to ask.

**Verdict: an ordering primitive, correct at what it does, and not an authority source.**

### The device registry, and the bearer token

Covered as a subfinding in area 8 and repeated here only for the enumeration's completeness.
`GET /api/v2/device/{device_id}` is a raw lookup of a row written by an open, length-validating
`POST /api/v2/device/register` (`dsm_storage_node/src/api/identity/device_api.rs:75-150,167-190`).
It is keyed by `d_o`, not `g_o`, so a verifier starting from a genesis cannot reach it. The single
signature it carries, `kyber_binding_sig`, is by the AK over `(device_id, genesis_hash, kyber_pk)`
(`dsm_sdk/src/sdk/kyber_identity.rs:35-82`) — it binds a Kyber key to whichever AK signed, and says
nothing about whether that AK belongs to `d_o`. An attacker's AK signs an equally valid binding
over a victim's `device_id`.

The `auth::device_auth` bearer token issued at registration (`dsm_storage_node/src/main.rs:216-220`)
gates object writes. It is access control derived from that same open registration, and it
authenticates nothing about identity.

### Structural observation: every chain in the system terminates at `AK_pk`

Worth recording because it explains why the gap stayed invisible. DSM has real, sound *relative*
authentication: the per-step EK certificate chain binds each ephemeral key to the prior chain head
and "lets a verifier walk the chain back to the device-attested `AK_pk`"
(`proto/dsm_app.proto:2282-2287`). Recovery authority chains to the AK. Kyber identity chains to
the AK. Vault-state composition chains a baseline anchor to a seq-0 birth anchor under the same key
(`dsm_sdk/src/sdk/vault_state_composition.rs:367-386`).

Every one of these chains is correct, and every one terminates at an `AK_pk` whose binding to `d_o`
is never independently checked. In a bilateral relationship that is adequate: the AK is pinned once
at contact-add and continuity is the property that matters afterward. It stops being adequate the
moment a verifier meets a **counterparty it never pinned** — which is exactly the foreign trader in
SoFi, and exactly why SoFi is where this surfaced.

## Conclusion

**No non-circular `g_o → R_G` edge exists today.** Under the canonical Genesis v2 profile there is
no genesis-committed public key for any candidate mechanism to be rooted in, and the one design
that would have supplied it is unimplemented and rooted in a genesis profile that was demoted to
optional.

What is missing is **not one check**. It is a **missing authenticated chain**, and a design is
finished only when a verifier holding `g_o` and a presented `(AK_pk, AttA)` can discharge the whole
composed predicate:

1. obtain the current or applicable Device Tree root for `g_o`, and authenticate it against
   something whose own legitimacy does not derive from that root;
2. verify an inclusion proof for `d_o` under exactly that authenticated root;
3. recompute `d_o = H("DSM/devid" ‖ AK_pk ‖ AttA)` from the independently presented material and
   require it to equal the included leaf;
4. only then treat `AK_pk` as owner authority.

Repairing any proper subset leaves the chain broken. In particular, publishing `AttA` closes step 3
and nothing else.

**Exit condition for the follow-up design.** It may proceed once step 1 has an answer — a named
authority, reachable from `g_o`, cryptographically authenticated, and demonstrably not deriving its
own standing from `R_G`. If no existing authority can supply it, that is itself the answer, and the
design's first decision becomes what new genesis-time commitment introduces one. Either way the
question is settled before the presentation object, its resolver and its publication form are
defined — see
[`docs/plans/2026-08-22-device-identity-presentation-semantics.md`](../plans/2026-08-22-device-identity-presentation-semantics.md).

## Reproducing this audit

```bash
grep -rho '"/api/v2/[^"]*"' dsm_storage_node/src/api --include='*.rs' | sort -u
```

Three routes carry `{genesis}`; the rest are keyed by device, address, vault or node.

```bash
git grep -ln 'RootBindingRecord' -- 'dsm_client/*' 'dsm_storage_node/*' 'proto/*'
git grep -ln 'DeviceTreeRootUpdateV1' -- 'dsm_client/*' 'dsm_storage_node/*' 'proto/*'
git grep -nw 'atta\|AttA' -- 'proto/*'
git grep -n 'derive_devid' -- 'dsm_client/*' 'dsm_storage_node/*' 'proto/*'
```

The `G` preimage is checked against the source rather than asserted: `derive_genesis_g` hashes
`genesis_nonce ‖ network_id ‖ genesis_version` and nothing else
(`dsm/src/core/identity/genesis_v2.rs:92-103`), and `create_genesis_v2` places the AK public key in
`GenesisState.signing_key`, outside `hash` (`dsm/src/core/identity/genesis.rs:509-518`).
