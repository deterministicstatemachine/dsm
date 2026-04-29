---
applyTo: '**'
---
A Formal Withdrawal Model for dBTC with Policy-Bound In-Flight
Conversion
Brandon "Cryptskii" Ramsay
March 19, 2026
This document formalizes the DSM withdrawal model for dBTC under policy-bound in-flight conversion,
with explicit supply-state transitions, compatibility requirements, executable settlement conditions,
successor-vault admission rules, and terminal resolution semantics.
Formal Withdrawal Model with Policy-Bound In-Flight Conversion
Definition 1 (Policy-Class Supply State). Fix a CPTA policy class P . Let
SP (t) ∈N, FP (t) ∈N, TP (t) := SP (t) + FP (t),
where:
• SP (t) is the spendable dBTC supply in DSM at state t,
• FP (t) is the in-flight dBTC supply in DSM at state t,
• TP (t) is the total DSM-side dBTC supply for policy class P.
Each dBTC unit in class P is, at every protocol state, in exactly one of the following mutually
exclusive states:
Spendable, InFlight, Burned.
Invariant 1 (Supply Conservation). For every policy class P and every DSM state t,
TP (t) = SP (t) + FP (t),
and TP may change only through protocol-authorized mint or final-burn transitions.
Definition 2 (Compatible Limbo Vault Set). For each policy class P , let
VP (t)
denote the set of live limbo vaults advertising compatibility with P at state t. A vault v is compatible
with P iff its Bitcoin-side spend predicate, collateral form, and settlement constraints satisfy the
CPTA requirements defining P.
Definition 3 (Withdrawal Intent). A withdrawal intent is a tuple
w = id(w), P (w), a(w), addrBTC(w),
where:
1
• id(w) is a unique withdrawal identifier,
• P (w) is the CPTA policy class of the committed dBTC,
• a(w) ∈N \{0}is the withdrawal amount,
• addrBTC(w) is the Bitcoin destination address.
Definition 4 (Withdrawal Admissibility). A withdrawal intent w is admissible at DSM state t iff
Admissible(w, t) := a(w) ≤SP (w)(t) ∧Unique id(w) ∧ValidPolicy P (w) ∧ValidBTCAddress addrBTC(w).
Definition 5 (In-Flight Commitment). If w is admissible at state t, then DSM may perform the
withdrawal-commit transition
Commit(w) : t →t′
,
defined by
SP (w)(t′) = SP (w)(t)−a(w), FP (w)(t′) = FP (w)(t) + a(w),
with all other policy-class balances unchanged except as required by protocol bookkeeping, and with
commitment record
C(w) = Committed.
Definition 6 (In-Flight Tumbler). Let w be a committed withdrawal intent. The in-flight tumbler
of w, denoted
Θ(w),
is the withdrawal-specific execution state induced by DSM-side commitment of amount a(w) under
policy class P (w). It is not the circulating token as such; rather, it is the committed conversion of
that token amount from spendable state into in-flight state.
Definition 7 (Witness Completion Material). Let w be committed and let v ∈VP (w)(t). The
witness-completion material for (w, v) is
U (w, v) := Derive Θ(w), P (w), v ,
where Derive is the protocol-deterministic derivation function.
Requirement 1 (Policy-Bound Derivation). For every committed withdrawal w and every vault v,
U (w, v) is defined only if
v ∈VP (w)(t).
Equivalently, witness-completion material is derivable only against a limbo vault compatible with the
same CPTA policy class as the committed in-flight dBTC.
Definition 8 (Executable Withdrawal Predicate). Let
Exec(w, v)
denote the predicate that the Bitcoin spend path of vault v is validly satisfiable using U (w, v) for
withdrawal w. Then withdrawal w is executable at state t iff
Executable(w, t) := C(w) = Committed ∧∃v ∈VP (w)(t) Exec(w, v).
2
Definition 9 (Bilateral Conversion Guard). The conversion of dBTC from DSM-side fungible
balance into Bitcoin-side settlement authority is guarded bilaterally. A withdrawal w may advance
toward settlement only if both of the following hold:
C(w) = Committed
DSM-side supply conversion
∧ ∃v ∈VP (w)(t) Exec(w, v)
Bitcoin-side executable collateral
.
Thus neither DSM-side commitment alone nor Bitcoin-side collateral availability alone is sufficient.
Definition 10 (Withdrawal Bitcoin Spend). Let
BitcoinSpend(w)
denote the predicate that the committed withdrawal w has been validly realized by a Bitcoin transaction
satisfying the protocol-defined spend path for some compatible vault v ∈VP (w), with an output paying
a(w) to addrBTC(w).
Definition 11 (Split Withdrawal and Successor Vault). A withdrawal may be either:
• full, consuming the selected vault with no remainder, or
• split, producing both
Outuser(w) = a(w), addrBTC(w)
and a remainder output encoded as a successor vault
v+(w).
Whenever a successor vault v+(w) exists, it is a newly created Bitcoin-side collateral object under
the same CPTA policy class P (w), distinct from the user payout output.
Definition 12 (Vault Admission Depth). Let dmin(P ) denote the canonical burial depth required
for admission of a Bitcoin-side vault into the DSM-recognized live collateral set for policy class P.
Definition 13 (Successor Admission Predicate). Let v+(w) be the successor vault produced by a
split withdrawal, when such a successor exists. Define
Admitted v+(w) := BitcoinUTXO v+(w) ∧ depth(v+(w)) ≥dmin(P (w)).
If no successor vault is produced, this predicate is vacuous.
Definition 14 (Withdrawal Resolution). A committed withdrawal w resolves on the withdrawal
side when
Resolved(w) := BitcoinSpend(w).
This resolution condition concerns only the user-directed Bitcoin payout. It is independent of whether
any successor vault has yet satisfied the burial rule for re-admission into the collateral grid.
Definition 15 (Final Burn Transition). If Resolved(w) holds for a committed withdrawal w, DSM
performs the final-burn transition
FP (w) := FP (w)−a(w),
3
sets
C(w) := Finalized,
and records
FinalBurn(w) = ⊤.
No corresponding restoration to SP (w) occurs.
If the withdrawal is split and produces a successor vault v+(w), that successor is not included in the
live redeemable collateral set until
Admitted v+(w)
holds.
Definition 16 (Refund Transition). If a committed withdrawal w fails to achieve BitcoinSpend(w)
under protocol-defined failure conditions, DSM performs the refund transition
FP (w) := FP (w)−a(w), SP (w) := SP (w) + a(w),
sets
C(w) := Refunded,
and records
Refunded(w) = ⊤.
Invariant 2 (Single Resolution). For every withdrawal intent w,
¬ FinalBurn(w) ∧Refunded(w).
Equivalently, no committed withdrawal may resolve both by final burn and by refund.
Invariant 3 (No Double Spendable Claim). For every policy class P and every withdrawal w
with P (w) = P , once Commit(w) occurs, the amount a(w) is excluded from spendable balance until
exactly one of the two terminal transitions occurs:
FinalBurn(w) or Refunded(w).
Hence DSM never permits the same dBTC amount to remain simultaneously spendable and re-
deemable.
Invariant 4 (Successor Burial Before Re-Admission). For every split withdrawal w producing
successor vault v+(w),
¬Admitted v+(w) ⇒ v+(w) / ∈VP (w)(t).
Equivalently, a successor vault may exist on Bitcoin before burial, but it is not re-admitted into the
DSM live collateral set until the canonical admission depth is reached.
Proposition 1 (Formal Characterization of the In-Flight Tumbler). A circulating dBTC unit is
not itself the missing Bitcoin-side witness component. Rather, upon DSM withdrawal commitment,
the corresponding amount is converted into an in-flight state
Θ(w),
derived under CPTA policy class P (w), and only this committed in-flight state may deterministically
induce witness-completion material U (w, v) for a compatible limbo vault v ∈VP (w)(t). Thus the
missing tumbler is the policy-bound in-flight conversion state, not the uncommitted token as such.
4
Proposition 2 (Formal Withdrawal Law). For a withdrawal intent w, redemption to Bitcoin is
protocol-valid iff
Withdraw(w, t) = C(w) = Committed
DSM-side commitment
∧ ∃v ∈VP (w)(t) Exec(w, v)
compatible BTC collateral
∧ P (v) = P (w)
same CPTA policy
If BitcoinSpend(w) is achieved, the committed amount resolves by final burn.
If BitcoinSpend(w) is not achieved under protocol-defined failure conditions, the committed amount
resolves by refund rather than burn.
Proposition 3 (Withdrawal Resolution Versus Vault Admission). The Bitcoin-side user payout
and any successor vault produced by the same withdrawal play distinct protocol roles.
• The user payout output resolves the committed withdrawal amount once BitcoinSpend(w) is
achieved.
• The successor vault, when present, is a newly created Bitcoin-side collateral object and requires
burial before re-admission into the DSM live collateral set.
Therefore the burial parameter applies to vault admission, including successor-vault admission, and
not as an additional hold on the user-directed withdrawal amount.
5