# Live DLV routing is blocked on an honest second-asset origin

**Status:** BLOCKED (owner ruling, 2026-08-29). Core DLV economics are complete and proven;
the live route cutover does not proceed.

## The boundary

```
Core DLV economics                          Live DLV routing
    Create write set     PROVEN                 dlv.create   BLOCKED
    Close write set      PROVEN                 dlv.close    BLOCKED
    Settle    0x0026     PROVEN                 dlv.settle   BLOCKED (transitively)
    Owner apply 0x0027   PROVEN                 dlv.reconcile BLOCKED (transitively)
```

The verifier can validate every DLV value operation (3.6 PR1–PR4, merged as #740–#744).
Production cannot originate the inputs those operations consume. Those are separate
properties, and only the second one is blocked.

## Why

Two independent blockers, either of which alone is sufficient:

```
A. Existing identities carry legacy device-state balances
     -> validated_root_or_activate()
     -> UnsupportedLegacyEconomicState
     -> admission never reaches build_write_set

B. A fresh identity can legitimately bootstrap ERA (the faucet's finite ticket
   allocation) but there is NO legitimate second-asset source into R_econ
     -> a two-asset DlvCreateFundedV2 is unreachable
```

`DlvCreateFundedV2` requires two admitted balance pre-leaves and a canonical AMM pair
requires two DISTINCT assets. Every other origin into a validated lineage is closed by
construction, and deliberately so:

| Path | Outcome | Where |
|---|---|---|
| ERA faucet tickets | the one live origin, ERA only | `faucet_claim_flow.rs` |
| `CreateToken` with `initial_supply > 0` | `CreateTokenInitialSupplyRequiresIssuancePredicate` | `write_set.rs:397` |
| `Mint` | `IssuancePredicateUndefined` | `write_set.rs:412` |
| `AuthorizedIssuance` credit source | fails closed; class `0x0029` unwritten | `provenance.rs:631` |
| `ValidatedPeerDebit` | recursive — the peer needed an origin first | `provenance.rs` |
| `SameTransitionMove` | same-asset; relocates, never originates | `provenance.rs:636` |

## What is NOT the fix

None of these is permitted as a way to unblock:

```
NO synthetic admitted heads          NO test-only provenance
NO "both legs ERA"                   NO implicit legacy snapshot
NO 0x0029 invented to unblock a PR   NO second faucet/bootstrap invented to save tests
NO bypass around validated_root_or_activate
```

The DLV route tests that fail once `dlv.create` is admission-gated are not a security
problem and must not be "fixed". They correctly show that the present market setup depends
on balances with no admissible `R_econ` history. Fabricating the missing provenance merely
to demonstrate reachability is the one thing that would make this worse.

## What unblocks it

A legitimate second-asset source predicate — its own design, its own decision, not smuggled
into a DLV plumbing PR. When one exists:

- beta exercises the live path on **fresh identities** that fund both assets through
  admitted origins;
- **no legacy migration protocol is required**, and none should be designed;
- existing balance-loaded identities continue to fail activation **by design** —
  `UnsupportedLegacyEconomicState` is preserved, not relaxed.

Only then does the live cutover (former 3.6 PR5/PR6) become reachable: PR6's settle and
owner-apply are blocked transitively, because there is no honestly admitted vault to
operate on.

## What landed instead

The one non-dead correction the cutover exploration surfaced, on
`feat/dlv-create-close-admission-cutover`: the admission builder's debit-mutation locator is
now structurally confined to `Operation::Transfer`. Its sole consumer is the online-transfer
wire; the "first mutation whose amount fell" scan is exact for a single-debit Transfer and
silently wrong for any multi-leg write set. The route scaffolding built during exploration
was reverted rather than shipped: unreachable code that looks implemented is worse than an
honest gap.
