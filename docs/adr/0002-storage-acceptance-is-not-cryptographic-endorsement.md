<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# ADR 0002 — Storage acceptance is not cryptographic endorsement

Status: accepted
Date: 2026-08-07

## Context

DSM storage nodes are non-authoritative infrastructure: they persist and serve
replicated bytes (device registrations, identity bindings, receipts) so that
clients can retrieve them. They are indexers, not authorities. The client holds
the trust roots — a peer's SPHINCS+ signing key (the **AK**) is established
out-of-band through the QR/BLE pairing, and the client verifies cryptographic
evidence itself.

A device identity binding ties a peer's ML-KEM (Kyber-768) public key to its
`(device_id, genesis_hash)` under the peer's AK:

```text
digest  = H(KYBER_IDENTITY_BINDING_TAG ‖ device_id ‖ genesis_hash ‖ kyber_pubkey)
binding = SPHINCS+_sign(AK_secret, digest)
verify  = SPHINCS+_verify(AK_public, digest, binding)   // AK_public is the trust root
```

A brief detour (PR #625, first iteration) had the storage node verify this
binding *before persistence*. Two problems made that the wrong place for it:

1. **It cannot establish trust.** The node can only verify the binding against
   the AK the registrant itself supplied in the request. That proves the
   submission is *internally consistent* — the registrant controls the AK it
   claims and signed the Kyber key under it — but the registrant chooses its own
   AK. A device can still bind any Kyber key to its own self-chosen identity. A
   peer with no contact record has no trusted AK to compare against, so the
   node's acceptance tells it nothing about identity.
2. **It quietly moves authority into the storage layer.** If clients treat "the
   node stored and served it" as endorsement, the storage layer becomes a
   de-facto certificate authority — the opposite of DSM's model.

## Decision

**A client may accept or cache peer Kyber (ML-KEM) material only when it can
establish a cryptographic chain from that material to an independently
authenticated peer AK, or to an equivalently authenticated pairing transcript.
Storage-node acceptance is never part of that trust chain.**

The test is a *proof chain*, not a function call. "Does this path call
`verify_kyber_identity_binding()`?" is the wrong question; the right question is
**"is the Kyber key bound — by a signature the client verified against the pinned
peer AK — to the identity it is being cached under?"** A path satisfies the
invariant in exactly one of two ways, and every consumer must land in one of
these or be **rejected**:

- **Authenticated by detached binding.** The client holds the pinned AK
  out-of-band and verifies a detached `kyber_binding_sig` over
  `H(TAG ‖ device_id ‖ genesis ‖ kyber_pk)` against that pinned AK before
  caching. (Node-served material is *always* this case — untrusted bytes, verified
  against the pinned AK.)
- **Authenticated by signed pairing transcript.** The Kyber public key is inside
  the exact bytes of a message the client already signature-verified against the
  pinned peer AK. If the verified transcript covers the Kyber key, a second
  detached check is redundant, not security-critical. If it does **not** cover the
  Kyber key, the transcript does not authenticate it and the path needs a detached
  binding — or is rejected.

Concretely:

- **Storage node — dumb, non-authoritative.** It enforces *structural* admission
  only: field presence, exact lengths (`device_id` 32, `genesis_hash` 32,
  `kyber_public_key` 1184), size ceilings, database invariants, and
  (out of scope here) rate/quota/authenticated-write limits. It stores the
  `kyber_binding_sig` as opaque bytes and serves it. It makes **no**
  identity-trust decision and runs **no** signature verification on registration
  content. "The node stored and served it" is never a link in the trust chain.

- **The pinned AK is itself a trust root and is never re-rooted from untrusted
  transport.** A node/peer-supplied AK that differs from the pinned AK is a
  substitution attempt — reject it; never overwrite the pinned AK from wire bytes
  (node quorum *or* BLE). A genuinely rotated AK is a new identity re-established
  through the explicit pairing flow.

- **Unknown peer ⇒ no chain ⇒ fail closed.** No independently authenticated AK
  means no authenticated Kyber identity. Outside the explicit pairing flow this
  fails closed. **No implicit TOFU.**

## Complete path matrix

Every client path that consumes or caches peer Kyber material, classified by how
(if at all) it chains to the pinned AK. Every row lands in exactly one of three
statuses — **authenticated by detached binding**, **authenticated by signed
pairing transcript**, or **rejected**. There is deliberately no fourth
"trusted because storage returned it" state. Cited against
`dsm_client/deterministic_state_machine/` on branch `fix/kyber-binding-verification`.

| # | Client path | Kyber source | Chain to pinned AK | Status | Enforced today? |
|---|---|---|---|---|---|
| 1 | Send-path repair from quorum (`app_router_impl.rs` `repair_contact_decision`) | node quorum | require returned AK == pinned AK, then verify detached `kyber_binding_sig` vs pinned AK before refresh; AK never overwritten | **Authenticated by detached binding** | ✅ (this PR — repair-path AK preservation) |
| 2 | Storage-route hydrate (`storage_routes.rs` :186–197) | node quorum | verify detached binding vs pinned `contact.public_key`; empty AK → fail closed; bind only if absent | **Authenticated by detached binding** | ✅ |
| 3 | Send-side encapsulation (`app_router_impl.rs` :1519–1546 → `receipts.rs` :149) | local cache | reads only the cache; every node-served writer of that cache is row 1/2; fail-closed on empty | **Authenticated (transitive)** | ✅ |
| 4 | QR contact-add (`contact_sdk.rs` :643; `resolve_counterparty_via_transport`) | — (QR carries no Kyber) | QR transcript authenticates the **signing AK only**; Kyber slot stored empty and later filled by row 1/2 | **Authenticated pairing transcript (AK); Kyber deferred** | ✅ |
| 5 | Unknown peer (no contact record) | node/wire | no pinned AK ⇒ no chain; online send requires an existing contact and aborts otherwise | **Rejected (fail closed, no TOFU)** | ✅ |
| 6 | BLE prepare-**request** → AK write (`bilateral_ble_handler.rs`, `bind_contact_public_key_if_absent`) | BLE wire, unsigned | first-write-wins: establish the AK only when absent; a *differing* wire AK is reported as a substitution and rejected — the pinned AK is preserved | **Rejected (must not re-root pinned AK)** | ✅ (this PR — first-write-wins) |
| 7 | BLE prepare-**response** → AK write (`bilateral_ble_handler.rs`, `bind_contact_public_key_if_absent`) | BLE wire, unsigned | same first-write-wins treatment | **Rejected (must not re-root pinned AK)** | ✅ (this PR — first-write-wins) |
| 8 | BLE prepare-**request** → Kyber bind (`bilateral_ble_handler.rs` :2338) | BLE wire | `handle_prepare_request` runs **no** signature verify before the bind; `BilateralPrepareRequest` carries no envelope signature and no `kyber_binding_sig` — the Kyber key is in **no** verified-against-pinned-AK message | **Rejected (gap)** | ❌ → **BLE P0 follow-up** |
| 9 | BLE prepare-**response** → Kyber bind (`bilateral_ble_handler.rs` :3114) | BLE wire | bind runs **before** the σ_B verify (:3242); σ_B covers only `"DSM/bilateral-sign\0" ‖ commitment_hash` (excludes the Kyber key) and verifies against the just-overwritten AK (tautology) | **Rejected (gap)** | ❌ → **BLE P0 follow-up** |

**Decisive question for the BLE rows** (8/9): *is the Kyber public key inside the
exact bytes that were successfully verified against the pinned peer AK before
`bind_contact_kyber_key_if_absent` runs?* Verified against source: **no** — no
signature covers the Kyber field on either BLE path. These are therefore real
gaps, not redundant checks. Closing them is a wire-format change (bind the Kyber
material into the signed BLE transcript, or add a detached `kyber_binding_sig` to
the prepare messages) that must be validated on two phones — tracked as the
**release-blocking BLE P0 follow-up**, deliberately kept out of #625 so the
evidence boundary (client-only, no proto) stays clean.

## Consequences

- **Resource abuse ≠ identity authentication.** Without node-side signature
  verification, a client can push cryptographic garbage into storage. That is a
  storage-abuse concern, addressed with structural validation, size caps, rate
  limits, quotas, and authenticated write permissions — **not** by moving
  identity authority into the node.

- **No legacy/TOFU path.** A binding served for a peer the client has never
  paired with is untrusted and unusable (row 5); the peer must be established
  in person (QR/BLE) first. DSM beta has no trust-on-first-use fallback.

- The storage node's own comment already states the model: *"the node is a dumb
  indexer: it enforces length/presence only; the cryptographic identity binding
  is verified client-side against the peer's AK."* This ADR makes that binding
  invariant explicit and repo-wide, and the matrix above makes each path's status
  auditable.
