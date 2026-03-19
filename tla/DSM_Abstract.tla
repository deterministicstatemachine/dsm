---- MODULE DSM_Abstract ----
EXTENDS Naturals, FiniteSets, TLAPS

(***************************************************************************
  DSM_Abstract: irreducible truth layer (clockless, deterministic)

  This module is intentionally tiny. It captures the core promises that must
  remain true as DSM grows:

  - NoDoubleSpend: a consumed activation/spend proof is never reusable.
  - Conservation / bounded issuance: emitted value is bounded by an abstract
    activation budget.
  - Monotone evolution: a commitment chain only advances forward.

  The concrete DSM model (DSM.tla) should refine this module via a mapping.

  Notes
  - We do *not* model shards, SMTs, inboxes, offline sessions, etc.
    Those are refinable mechanisms.
  - We keep everything clockless. "step"/"commit" are logical counters.
***************************************************************************)

CONSTANTS
  DeviceIds,     \* universe of identities/devices
  MaxStep,       \* bound for step-limited regressions
  InitialRemaining,
  InitialBudget

ASSUME InitConstants ==
  /\ InitialRemaining \in Nat
  /\ InitialBudget \in Nat

VARIABLES
  \* Abstract token accounting (can be specialized by mapping)
  remaining,     \* remaining undistributed supply (Nat)

  \* Abstract activation budget (units that allow emissions)
  budget,        \* Nat

  \* Abstract spent-set: consumed activation proofs / spend proofs
  spent,         \* SUBSET Nat

  \* Monotone commitment chain head (logical, not wall-clock)
  commit,        \* Nat

  \* Monotone transition counter for bounded TLC exploration
  step           \* Nat

vars == <<remaining, budget, spent, commit, step>>

ProofSpace == 0..(InitialRemaining + InitialBudget + MaxStep)

TypeInv ==
  /\ remaining \in Nat
  /\ budget \in Nat
  /\ spent \subseteq ProofSpace
  /\ commit \in Nat
  /\ step \in Nat

Init ==
  /\ remaining = InitialRemaining
  /\ budget = InitialBudget
  /\ spent = {}
  /\ commit = 0
  /\ step = 0

(***************************************************************************
  Actions

  These actions are the "meaning" of DSM-level operations.
  Concrete mechanisms must map to one of these.
***************************************************************************)

\* Activate increases budget by 1 and advances commitment.
Activate ==
  /\ budget' = budget + 1
  /\ remaining' = remaining
  /\ spent' = spent
  /\ commit' = commit + 1
  /\ step' = step + 1

\* Emit consumes exactly one unspent proof, issues 1 unit, and advances commit.
\* Emit is only allowed if there is remaining supply and remaining budget.
Emit ==
  /\ remaining > 0
  /\ budget > 0
  /\ \E p \in ProofSpace :
        /\ p \notin spent
        /\ spent' = spent \cup {p}
  /\ remaining' = remaining - 1
  /\ budget' = budget - 1
  /\ commit' = commit + 1
  /\ step' = step + 1

\* Spend models a non-emission spend that also consumes a proof.
\* (In a fuller abstract layer, Spend would reallocate balances; here we
\*  only enforce the single-use property and monotone commit.)
Spend ==
  /\ \E p \in ProofSpace :
        /\ p \notin spent
        /\ spent' = spent \cup {p}
  /\ UNCHANGED <<remaining, budget>>
  /\ commit' = commit + 1
  /\ step' = step + 1

\* NoOp represents stuttering / actions that have no semantic effect besides
\* advancing the logical step (e.g., observation, inbox scan bounded by step).
NoOp ==
  /\ UNCHANGED <<remaining, budget, spent, commit>>
  /\ step' = step + 1

Stutter ==
  /\ remaining' = remaining
  /\ budget' = budget
  /\ spent' = spent
  /\ commit' = commit
  /\ step' = step

Next == Activate \/ Emit \/ Spend \/ NoOp

Spec == Init /\ [][Next]_vars

\* Bounded exploration constraint (used by TLC configs).
StepBound == step \in 0..MaxStep

(***************************************************************************
  Abstract invariants (state predicates)

  NOTE: Monotonicity properties (spent/commit never decrease) are *temporal*
  and should be checked as properties, not invariants, via `[](...)`.
***************************************************************************)

AbstractSafety == TypeInv

\* Temporal properties (recommended for configs)
\* - spent never shrinks
SpentNeverShrinks == [][spent \subseteq spent']_vars

\* - commit never decreases
CommitNeverDecreases == [][commit <= commit']_vars

THEOREM AbstractInit == Init => TypeInv
  BY InitConstants DEF Init, TypeInv

LEMMA ActivatePreservesType ==
  ASSUME TypeInv, Activate
  PROVE TypeInv'
  BY SMT DEF TypeInv, Activate, ProofSpace

LEMMA EmitPreservesType ==
  ASSUME TypeInv, Emit
  PROVE TypeInv'
  BY SMT DEF TypeInv, Emit, ProofSpace

LEMMA SpendPreservesType ==
  ASSUME TypeInv, Spend
  PROVE TypeInv'
  BY SMT DEF TypeInv, Spend, ProofSpace

LEMMA NoOpPreservesType ==
  ASSUME TypeInv, NoOp
  PROVE TypeInv'
  BY SMT DEF TypeInv, NoOp, ProofSpace, vars

LEMMA AbstractNextPreservesType ==
  ASSUME TypeInv, Next
  PROVE TypeInv'
<1>1. CASE Activate
  BY <1>1, ActivatePreservesType
<1>2. CASE Emit
  BY <1>2, EmitPreservesType
<1>3. CASE Spend
  BY <1>3, SpendPreservesType
<1>4. CASE NoOp
  BY <1>4, NoOpPreservesType
<1> QED
  BY <1>1, <1>2, <1>3, <1>4 DEF Next

LEMMA AbstractStutterPreservesType ==
  ASSUME TypeInv, Stutter
  PROVE TypeInv'
  BY Zenon DEF TypeInv, Stutter

THEOREM AbstractStep ==
  ASSUME TypeInv, [Next]_vars
  PROVE TypeInv'
<1>1. CASE Next
  BY <1>1, AbstractNextPreservesType
<1>2. CASE UNCHANGED vars
  BY <1>2, AbstractStutterPreservesType DEF vars, Stutter
<1> QED
  BY <1>1, <1>2

THEOREM AbstractSafetyTheorem == Spec => []TypeInv
<1>1. Init => TypeInv
  BY AbstractInit
<1>2. TypeInv /\ [Next]_vars => TypeInv'
  BY AbstractStep
<1> QED
  BY PTL, <1>1, <1>2 DEF Spec

LEMMA AbstractNextSpentStep ==
  ASSUME Next
  PROVE spent \subseteq spent'
  BY Zenon DEF Next, Activate, Emit, Spend, NoOp

LEMMA AbstractStutterSpentStep ==
  ASSUME Stutter
  PROVE spent \subseteq spent'
  BY Zenon DEF Stutter

THEOREM AbstractSpentStep ==
  ASSUME [Next]_vars
  PROVE spent \subseteq spent'
<1>1. CASE Next
  BY <1>1, AbstractNextSpentStep
<1>2. CASE UNCHANGED vars
  BY <1>2, AbstractStutterSpentStep DEF vars, Stutter
<1> QED
  BY <1>1, <1>2

LEMMA AbstractNextCommitStep ==
  ASSUME TypeInv, Next
  PROVE commit <= commit'
<1>1. CASE Activate
  BY <1>1, SMT DEF TypeInv, Activate
<1>2. CASE Emit
  BY <1>2, SMT DEF TypeInv, Emit
<1>3. CASE Spend
  BY <1>3, SMT DEF TypeInv, Spend
<1>4. CASE NoOp
  BY <1>4, SMT DEF TypeInv, NoOp, vars
<1> QED
  BY <1>1, <1>2, <1>3, <1>4 DEF Next

LEMMA AbstractStutterCommitStep ==
  ASSUME TypeInv, Stutter
  PROVE commit <= commit'
  BY SMT DEF TypeInv, Stutter

THEOREM AbstractCommitStep ==
  ASSUME TypeInv, [Next]_vars
  PROVE commit <= commit'
<1>1. CASE Next
  BY <1>1, AbstractNextCommitStep
<1>2. CASE UNCHANGED vars
  BY <1>2, AbstractStutterCommitStep DEF vars, Stutter
<1> QED
  BY <1>1, <1>2

THEOREM AbstractSpentMonotone == Spec => [][spent \subseteq spent']_vars
  BY PTL, AbstractSpentStep DEF Spec

THEOREM AbstractCommitMonotone == Spec => [][commit <= commit']_vars
<1>1. Init => TypeInv
  BY AbstractInit
<1>2. TypeInv /\ [Next]_vars => TypeInv'
  BY AbstractStep
<1>3. TypeInv /\ [Next]_vars => commit <= commit'
  BY AbstractCommitStep
<1> QED
  BY PTL, <1>1, <1>2, <1>3 DEF Spec

====
