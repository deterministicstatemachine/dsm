---- MODULE DSM_dBTC_Abstract ----
EXTENDS Naturals, FiniteSets, TLAPS

(***************************************************************************
  DSM_dBTC_Abstract: irreducible truth layer for dBTC Bitcoin bridge
  ===================================================================

  This module is intentionally tiny. It captures the core promises of
  the dBTC bridge that must remain true as the implementation grows:

  - Conservation: total dBTC supply (spendable + in-flight) equals total
    confirmed Bitcoin in the vault grid. (dBTC paper §19, Property 12)
  - No stranded value: a failed in-flight withdrawal never destroys value.
    It either settles or refunds. (dBTC paper §15, Property 9)
  - Bounded supply: total dBTC never exceeds MaxSupply. (21M BTC)
  - Monotone settlement: settled withdrawals never un-settle.

  The concrete DSM_dBTC model should refine this module via a mapping.

  Notes
  - We do *not* model vaults, successors, storage nodes, bearer η, or
    HTLC scripts. Those are refinable mechanisms.
  - We keep everything clockless. "step" is a logical counter.
  - Bitcoin is modeled as an abstract oracle that confirms or rejects.
    See DSM_dBTC_TrustReduction.tla for the focused model that makes the
    mainnet settlement assumptions explicit.
  - Cryptographic operations are assumed sound (same convention as
    DSM_Tripwire.tla).
***************************************************************************)

CONSTANTS
  MaxSupply,    \* maximum dBTC supply in satoshis (= 21M * 10^8)
  MaxStep       \* bound for step-limited regressions

ASSUME AbstractConstants ==
  /\ MaxSupply \in Nat
  /\ MaxStep \in Nat

VARIABLES
  \* Total spendable dBTC across all bearers (Nat)
  spendable,

  \* Total dBTC committed to in-flight withdrawals (Nat)
  inflight,

  \* Total confirmed BTC in live vault grid (Nat)
  \* Confirmed means depth >= d_min.
  gridBacking,

  \* Total settled (finalized burn) count — monotone counter
  settled,

  \* Monotone transition counter for bounded TLC exploration
  step

vars == <<spendable, inflight, gridBacking, settled, step>>

TypeInv ==
  /\ spendable \in Nat
  /\ inflight \in Nat
  /\ gridBacking \in Nat
  /\ settled \in Nat
  /\ step \in Nat

\* =========================================================================
\* dBTC Conservation Law (Spec §19, Property 12)
\*
\* At all times, total dBTC supply equals total Bitcoin held in the
\* compatible vault grid:
\*   spendable + inflight = gridBacking
\*
\* This is the fundamental safety property of the bridge.
\* =========================================================================
ConservationInvariant == spendable + inflight = gridBacking

BoundedSupply == spendable + inflight <= MaxSupply

AbstractSafety ==
  /\ TypeInv
  /\ ConservationInvariant
  /\ BoundedSupply

Init ==
  /\ spendable = 0
  /\ inflight = 0
  /\ gridBacking = 0
  /\ settled = 0
  /\ step = 0

(***************************************************************************
  Actions

  These actions are the "meaning" of dBTC bridge operations.
  Concrete mechanisms must map to one of these.
***************************************************************************)

\* Deposit: BTC enters the grid, dBTC is minted.
\* Both sides increase by the same amount (conservation preserved).
Deposit(amount) ==
  /\ amount > 0
  /\ spendable + inflight + amount <= MaxSupply
  /\ spendable' = spendable + amount
  /\ gridBacking' = gridBacking + amount
  /\ UNCHANGED <<inflight, settled>>
  /\ step' = step + 1

\* Transfer: move dBTC between bearers. Grid unchanged.
\* At the abstract level this is a no-op on aggregates.
Transfer ==
  /\ UNCHANGED <<spendable, inflight, gridBacking, settled>>
  /\ step' = step + 1

\* Commit: dBTC moves from spendable to in-flight.
\* Total supply unchanged, grid unchanged. (Spec §9, Definition 10)
Commit(amount) ==
  /\ amount > 0
  /\ spendable >= amount
  /\ spendable' = spendable - amount
  /\ inflight' = inflight + amount
  /\ UNCHANGED <<gridBacking, settled>>
  /\ step' = step + 1

\* Settle: in-flight dBTC is burned, BTC leaves the grid.
\* Both sides decrease by the same amount. (Spec §14, Definition 14)
Settle(amount) ==
  /\ amount > 0
  /\ inflight >= amount
  /\ gridBacking >= amount
  /\ inflight' = inflight - amount
  /\ gridBacking' = gridBacking - amount
  /\ settled' = settled + 1
  /\ UNCHANGED <<spendable>>
  /\ step' = step + 1

\* Refund: in-flight dBTC returns to spendable.
\* Total supply unchanged, grid unchanged. (Spec §15, Definition 15)
Refund(amount) ==
  /\ amount > 0
  /\ inflight >= amount
  /\ inflight' = inflight - amount
  /\ spendable' = spendable + amount
  /\ UNCHANGED <<gridBacking, settled>>
  /\ step' = step + 1

\* VaultExpire: a live vault's BTC is reclaimed (e.g., CLTV timeout).
\* Grid backing decreases but no dBTC was in-flight for this vault.
\* This can only happen if the corresponding dBTC has already been settled
\* or was never minted. For conservation: only allowed when no dBTC
\* references this backing. Modeled as gridBacking decrease paired with
\* an equal spendable decrease (depositor reclaims and burns their dBTC).
VaultExpire(amount) ==
  /\ amount > 0
  /\ gridBacking >= amount
  /\ spendable >= amount
  /\ gridBacking' = gridBacking - amount
  /\ spendable' = spendable - amount
  /\ UNCHANGED <<inflight, settled>>
  /\ step' = step + 1

NoOp ==
  /\ UNCHANGED <<spendable, inflight, gridBacking, settled>>
  /\ step' = step + 1

Stutter ==
  /\ spendable' = spendable
  /\ inflight' = inflight
  /\ gridBacking' = gridBacking
  /\ settled' = settled
  /\ step' = step

Next ==
  \/ \E a \in 1..MaxSupply : Deposit(a)
  \/ Transfer
  \/ \E a \in 1..MaxSupply : Commit(a)
  \/ \E a \in 1..MaxSupply : Settle(a)
  \/ \E a \in 1..MaxSupply : Refund(a)
  \/ \E a \in 1..MaxSupply : VaultExpire(a)
  \/ NoOp

Spec == Init /\ [][Next]_vars

\* Bounded exploration constraint (used by TLC configs).
StepBound == step \in 0..MaxStep

(***************************************************************************
  Temporal properties
***************************************************************************)

\* Settlement is monotone — settled count never decreases.
SettledNeverDecreases == [][settled <= settled']_vars

\* In-flight can only change via Commit (+), Settle (-), or Refund (-).
\* It never goes negative.
InFlightNonNegative == inflight >= 0

(***************************************************************************
  TLAPS Proofs — Init and action-preservation of AbstractSafety
***************************************************************************)

THEOREM AbstractInit == Init => AbstractSafety
  BY DEF Init, AbstractSafety, TypeInv, ConservationInvariant, BoundedSupply

LEMMA DepositPreservesAbstractSafety ==
  ASSUME AbstractSafety, NEW a \in Nat, a > 0, Deposit(a)
  PROVE AbstractSafety'
  BY SMT DEF AbstractSafety, TypeInv, ConservationInvariant, BoundedSupply, Deposit

LEMMA TransferPreservesAbstractSafety ==
  ASSUME AbstractSafety, Transfer
  PROVE AbstractSafety'
  BY DEF AbstractSafety, TypeInv, ConservationInvariant, BoundedSupply, Transfer

LEMMA CommitPreservesAbstractSafety ==
  ASSUME AbstractSafety, NEW a \in Nat, a > 0, Commit(a)
  PROVE AbstractSafety'
  BY SMT DEF AbstractSafety, TypeInv, ConservationInvariant, BoundedSupply, Commit

LEMMA SettlePreservesAbstractSafety ==
  ASSUME AbstractSafety, NEW a \in Nat, a > 0, Settle(a)
  PROVE AbstractSafety'
  BY SMT DEF AbstractSafety, TypeInv, ConservationInvariant, BoundedSupply, Settle

LEMMA RefundPreservesAbstractSafety ==
  ASSUME AbstractSafety, NEW a \in Nat, a > 0, Refund(a)
  PROVE AbstractSafety'
  BY SMT DEF AbstractSafety, TypeInv, ConservationInvariant, BoundedSupply, Refund

LEMMA VaultExpirePreservesAbstractSafety ==
  ASSUME AbstractSafety, NEW a \in Nat, a > 0, VaultExpire(a)
  PROVE AbstractSafety'
  BY SMT DEF AbstractSafety, TypeInv, ConservationInvariant, BoundedSupply, VaultExpire

LEMMA NoOpPreservesAbstractSafety ==
  ASSUME AbstractSafety, NoOp
  PROVE AbstractSafety'
  BY DEF AbstractSafety, TypeInv, ConservationInvariant, BoundedSupply, NoOp

LEMMA StutterPreservesAbstractSafety ==
  ASSUME AbstractSafety, Stutter
  PROVE AbstractSafety'
  BY DEF AbstractSafety, TypeInv, ConservationInvariant, BoundedSupply, Stutter

THEOREM AbstractStep ==
  ASSUME AbstractSafety, [Next]_vars
  PROVE AbstractSafety'
<1>1. CASE \E a \in 1..MaxSupply : Deposit(a)
  BY <1>1, DepositPreservesAbstractSafety
<1>2. CASE Transfer
  BY <1>2, TransferPreservesAbstractSafety
<1>3. CASE \E a \in 1..MaxSupply : Commit(a)
  BY <1>3, CommitPreservesAbstractSafety
<1>4. CASE \E a \in 1..MaxSupply : Settle(a)
  BY <1>4, SettlePreservesAbstractSafety
<1>5. CASE \E a \in 1..MaxSupply : Refund(a)
  BY <1>5, RefundPreservesAbstractSafety
<1>6. CASE \E a \in 1..MaxSupply : VaultExpire(a)
  BY <1>6, VaultExpirePreservesAbstractSafety
<1>7. CASE NoOp
  BY <1>7, NoOpPreservesAbstractSafety
<1>8. CASE UNCHANGED vars
  BY <1>8, StutterPreservesAbstractSafety DEF vars, Stutter
<1> QED
  BY <1>1, <1>2, <1>3, <1>4, <1>5, <1>6, <1>7, <1>8 DEF Next

THEOREM AbstractSafetyTheorem == Spec => []AbstractSafety
<1>1. Init => AbstractSafety
  BY AbstractInit
<1>2. AbstractSafety /\ [Next]_vars => AbstractSafety'
  BY AbstractStep
<1> QED
  BY PTL, <1>1, <1>2 DEF Spec

====
