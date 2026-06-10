---
applyTo: '**'
---

# Custom-Token Policy Validity and Per-Transfer Readiness

Normative doctrine for how a DSM device installs a token policy and how a token
transfer is authorized with respect to that policy. This governs all fungible and
non-fungible custom (CPTA) tokens in addition to the builtin tokens (ERA, dBTC).

Each clause is marked **Layer A** (normative and realized in the current
implementation) or **Layer B** (normative design intent, NOT yet shipped — tracked
by the referenced issue; MUST NOT be relied upon as an acceptance criterion until
that issue closes). See the Enforcement Surfaces table at the end.

A DSM token policy MUST NEVER be absorbed from a counterparty, a transaction
envelope, an inbox sync, a contact sync, an offline exchange, or arbitrary
peer-supplied bytes. Peer-supplied data may help *locate* a policy; it is never
*authority*.

## 1. Policy commitment (CPTA) — Layer A

The canonical policy commitment is the domain-separated BLAKE3 hash of the
canonical CPTA bytes:

    policy_commit = BLAKE3-256("DSM/cpta\0" || canonical_cpta_bytes)

`canonical_cpta_bytes` is the deterministic Protobuf serialization of the policy
object (Envelope wire v3), implemented as the Rust core `TokenPolicy` / `PolicyFile`
hashed via `PolicyAnchor::from_policy`. If sender and recipient do not hold the exact
same canonical policy bytes, their `policy_commit` values differ, every digest that
binds `policy_commit` changes, and verification fails.

## 2. Local policy installation — authoritative source only

Installation is **one time per device per token policy**. A device MAY populate a
token policy for itself ONLY from the authoritative source of truth — the original
CPTA / root anchor / issuer-or-root-signed policy anchor / canonical policy source
path. The policy bytes MUST be fetched independently, verified against the official
anchor path, and hashed under the §1 rule.

A token is locally installed only if all hold:

1. The policy bytes were obtained from the authoritative source of truth.
2. The policy anchor or issuer/root signature verifies. *(Issuer/root-signature
   verification is **Layer B**; current anchors are content-addressed only.)*
3. The canonical policy bytes hash exactly to `policy_commit`.
4. The policy is stored locally as an installed policy record.
5. The token namespace, token genesis, balance bucket, and `policy_commit` are
   bound together locally.

Policy bytes MUST NOT be sourced from: an offline peer, an online sender, a
transaction envelope, an inbox sync, a contact sync, arbitrary storage bytes, a
retrieval hint without anchor verification, or peer-supplied policy metadata.

**Layer A:** install/verify(content-address)/cache exists (`TokenPolicySystem`,
`PolicyCache` token_id→anchor, filesystem `PolicyStore`, CPTA fetch-verify-cache).
**Layer B:** issuer/root-signature verification of the anchor.

## 3. No automatic absorption

An incoming transfer (online object, offline exchange, inbox/contact sync) MUST NOT
automatically add, accept, credit, install, or display a token policy. Such an object
may carry a `policy_commit` or retrieval hint, but that neither populates the token
nor grants authority. The recipient MUST independently resolve the policy through the
authoritative source of truth and verify it before crediting balance, creating a
balance bucket, applying the transfer, or treating the token as installed. If the
recipient cannot verify the incoming reference against the authoritative source, the
object MUST fail closed (or remain quarantined) and MUST NOT mutate balances.

**Layer A** (online): the receiver resolves `policy_commit` from its own installed
policy and fails closed on an unresolved custom token; the operation carries only
`token_id`, so a peer cannot inject a `policy_commit`. **This branch** makes the
bilateral path consistent (was: silent skip).

## 4. policy_commit bound in every transfer — Layer A (§9.5)

Per whitepaper §9.5: *"All TokenOps MUST include `policy_commit`; verifiers reject if
it differs from the token's creation `policy_commit`."* Every transfer / precommit /
send digest MUST bind `policy_commit`. The full policy bytes need not be carried; the
compact `policy_commit` MUST be bound every time.

A transfer/precommit/send object MUST bind at least: `token_id` (or token_genesis),
`policy_commit`, sender identity, recipient identity, amount, parent_tip /
relationship context, session nonce / send context, and (Layer B) the counterparty
readiness digest.

**This branch** adds the required `policy_commit` field to the signed
`Operation::Transfer` and rejects on missing/mismatched commit at receive; balance
buckets are bound to `policy_commit` at the mutation chokepoint.

## 5. Per-transfer counterparty readiness — Layer B

Local installation is NOT sufficient to send or receive. For EVERY transfer, each
side MUST verify that the other side operates under the same exact canonical
`policy_commit P`. A valid transfer is bound to one exact `P`:

    Sender local policy hash == P
    Recipient local policy hash == P
    Counterparty readiness proof binds P
    Transfer precommit/send digest binds P

Readiness is **per transfer**, not a one-time approval, and is **mode-separated**:
online readiness does not satisfy offline readiness, and vice versa.

- **Online (b0x):** before creating the send object, the sender fetches the
  recipient's published readiness object from the recipient's online
  identity/storage/inbox surface and verifies it: recipient-signed, references the
  exact `policy_commit`, traces to the authoritative anchor, matches recipient
  identity, valid for the current send context. Only then is the send object created,
  binding the recipient readiness digest. The recipient independently re-verifies on
  ingest.
- **Offline (direct):** both devices already hold the source-of-truth-installed
  policy and exchange direct per-transfer readiness attestations binding token,
  `policy_commit`, identities, relationship context, parent_tip, session nonce, and
  the local install-record digest. Each verifies the other before any precommit
  exists.

All of §5 is **Layer B** (tracked — see table); no per-transfer policy-readiness
attestation exists today.

## 6. Hard validity rule

    CanTransferToken(A, B, token_id, policy_commit, mode) ==
        SourceTruthPolicyInstalled(A, policy_commit)
        && SourceTruthPolicyInstalled(B, policy_commit)
        && CounterpartyReadinessVerifiedForThisTransfer(A, B, policy_commit, mode)
        && CounterpartyReadinessVerifiedForThisTransfer(B, A, policy_commit, mode)
        && TransferDigestBinds(policy_commit)
        && BalanceBucketBoundToPolicy(token_id, policy_commit)

If any conjunct is false, the transfer fails closed before balance mutation. The
`SourceTruthPolicyInstalled`, `TransferDigestBinds`, and `BalanceBucketBoundToPolicy`
conjuncts are realized incrementally (this branch + issues below); the
`CounterpartyReadinessVerifiedForThisTransfer` conjuncts are Layer B.

## 7. Security properties

This doctrine prevents: fake-token injection, policy spoofing, ticker/alias and
namespace confusion, peer-supplied policy absorption, contact-sync and inbox-sync
poisoning, arbitrary balance-bucket creation, accepting a transfer under a policy the
counterparty does not actually hold, and accepting a transfer where sender and
recipient are not bound to the same canonical policy.

## Enforcement Surfaces (status)

| Surface | Status | Tracking |
|---|---|---|
| CPTA commit rule `policy_commit = H("DSM/cpta\0" \|\| bytes)` | Layer A | shipped (§9.3) |
| Local install / content-address verify / cache | Layer A | shipped |
| Issuer/root-signed anchor verification | Layer B | #466 |
| No auto-absorption, fail-closed (online) | Layer A | shipped |
| No auto-absorption, fail-closed (bilateral) | Layer A | **this branch** |
| `policy_commit` bound in signed `Operation::Transfer` + reject on mismatch | Layer A | **this branch** (#467) |
| By-construction balance conservation at `DeviceState::advance` | Layer A | **this branch** (#448) |
| Receiver-side local policy-install verification before apply | Layer B | #468 |
| Sender-side readiness preflight before online send | Layer B | #469 |
| Online recipient published readiness object/proof | Layer B | #470 |
| Offline direct per-transfer readiness exchange | Layer B | #471 |
| Fail-closed test matrix (missing/mismatched/stale/peer-supplied) | Layer B | #472 |
| Extend `policy_commit` binding to Mint/Burn/CreateToken (§9.5) | Layer B | #473 |

**Custom-token transfer readiness is INCOMPLETE** until the Layer-B issues above
close. Until then, custom-token transfers enforce policy_commit binding +
conservation + fail-closed, but NOT full per-transfer counterparty readiness.
