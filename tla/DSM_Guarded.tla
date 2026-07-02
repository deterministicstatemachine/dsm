---- MODULE DSM_Guarded ----
\* ===========================================================================
\* DSM Guarded Linear Constraint System — key-scoped fork exclusion.
\*
\* Machine-checkable realization of Appendix B of Ramsay, "Deterministic State
\* Machines as Guarded Linear Constraint Systems" (June 2026). This is the
\* GENERAL key-scoped model: uniqueness holds per resource consumption key, a
\* guard family decides realization, candidate forks are permitted but realized
\* forks are not, and disjoint resources may progress concurrently.
\*
\* Relation to DSM_Tripwire.tla: that module proves the bilateral-tip SPECIAL
\* CASE (uniqueness keyed on the concrete pair (rel, oldTip), TLC-checked). This
\* module proves the same property keyed on an ABSTRACT resource consumption key
\* over an arbitrary guard family; (rel, oldTip) is one instantiation of `key`.
\*
\* The discharged universal proof of the central theorems (realized_unique_at_key
\* / guarded_tripwire) lives in lean4/DSMGuardedTripwire.lean (those theorems
\* depend on NO axioms). This module model-checks the same Safety property over a
\* concrete finite guard family, and the companion config DSM_Guarded_Fork.cfg
\* demonstrates the property has TEETH: a malformed (key-split) guard family
\* genuinely forks and TLC reports the violation.
\* ===========================================================================
EXTENDS Naturals, FiniteSets

CONSTANTS
    State,      \* finite set of DSM states (model values)
    Key,        \* finite set of resource consumption keys (model values)
    Candidate   \* finite set of candidate records
                \*   [parent |-> State, succ |-> State, key |-> Key,
                \*    bid |-> Nat, guard |-> BOOLEAN]

VARIABLES
    current,    \* the current realized state
    consumed,   \* Sigma: set of resource consumption keys already consumed
    realized,   \* set of realized successor states
    pending,    \* delivered-but-not-yet-realized candidates (async delivery)
    ledger      \* realized-step receipts [parent, key, succ, bid], the trace history

Vars == <<current, consumed, realized, pending, ledger>>

\* ---------------------------------------------------------------------------
\* Candidate accessors (paper Def 11, 27, 29)
\* ---------------------------------------------------------------------------
Keys(c)      == {c.key}        \* the resource consumption key set of c
Parent(c)    == c.parent
Successor(c) == c.succ

\* ---------------------------------------------------------------------------
\* Layered realization predicate (paper Def 36-42)
\* ---------------------------------------------------------------------------
CandidateOK(c)  == c \in Candidate          \* committed candidate (Def 36)
GuardOK(c)      == c.guard = TRUE            \* fulfilled branch (Def 37, Def 18)
StructuralOK(c) == c.succ \in State          \* canonical recompute (Def 38)
PolicyOK(c)     == TRUE                       \* admissible policy accepts (Def 39)
ModeOK(c)       == TRUE                       \* online mode (Def 40)
LinearityOK(c)  == c.key \notin consumed      \* key absent before step (Def 31/32)

Step(c) ==
    /\ CandidateOK(c)
    /\ GuardOK(c)
    /\ StructuralOK(c)
    /\ LinearityOK(c)
    /\ PolicyOK(c)
    /\ ModeOK(c)

\* ---------------------------------------------------------------------------
\* Transitions
\* ---------------------------------------------------------------------------
\* Async delivery: a candidate may be delivered (adversary may reorder/replay)
\* without yet being realized.
Deliver(c) ==
    /\ c \in Candidate
    /\ pending' = pending \cup {c}
    /\ UNCHANGED <<current, consumed, realized, ledger>>

\* Realization: a delivered candidate adjacent to the current state whose guard
\* is fulfilled and whose key is unconsumed advances the state and consumes the
\* key (paper Def 41 Step + Realize action of App B). The accepted receipt is
\* appended to the ledger: the ledger is the realized history of this verifier.
Realize(c) ==
    /\ c \in pending
    /\ Parent(c) = current
    /\ Step(c)
    /\ current'  = Successor(c)
    /\ consumed' = consumed \cup Keys(c)
    /\ realized' = realized \cup {Successor(c)}
    /\ ledger'   = ledger \cup {[parent |-> Parent(c), key |-> c.key,
                                 succ |-> Successor(c), bid |-> c.bid]}
    /\ pending'  = pending \ {c}

Init ==
    /\ current \in State
    /\ consumed = {}
    /\ realized = {}
    /\ pending  = {}
    /\ ledger   = {}

Next == \E c \in Candidate : Deliver(c) \/ Realize(c)

Spec == Init /\ [][Next]_Vars

\* ---------------------------------------------------------------------------
\* Type invariant
\* ---------------------------------------------------------------------------
TypeOK ==
    /\ current  \in State
    /\ consumed \subseteq Key
    /\ realized \subseteq State
    /\ pending  \subseteq Candidate
    /\ ledger   \subseteq [parent : State, key : Key, succ : State, bid : Nat]

\* ---------------------------------------------------------------------------
\* Key-scoped step relation and safety (paper Def 42, 44, 52; Thm 2, 4)
\* ---------------------------------------------------------------------------
\* Step_K: a realized step from s1 to s2 consuming key k. Depends on `consumed`
\* through LinearityOK, so it is re-evaluated in every reachable state.
StepAtKey(s1, s2, k) ==
    /\ s1 \in State
    /\ s2 \in State
    /\ k  \in Key
    /\ \E c \in Candidate :
        /\ Parent(c)    = s1
        /\ Successor(c) = s2
        /\ k \in Keys(c)
        /\ Step(c)

\* Theorem 2: at most one realized successor per consumed parent resource.
RealizedUniqueAtKey ==
    \A s1, s2, s3 \in State : \A k \in Key :
        (StepAtKey(s1, s2, k) /\ StepAtKey(s1, s3, k)) => (s2 = s3)

\* Theorem 4: no key-scoped realized fork (Def 52).
NoRealizedForkAtKey ==
    \A s1, s2, s3 \in State : \A k \in Key :
        ~ (StepAtKey(s1, s2, k) /\ StepAtKey(s1, s3, k) /\ s2 # s3)

\* The DSM guarded safety property (paper Thm 4 / Main Result Thm 15, key scope).
Safety == RealizedUniqueAtKey /\ NoRealizedForkAtKey

\* ---------------------------------------------------------------------------
\* Trace-level (realized-history) uniqueness. `Safety` above states the paper's
\* Thm 2/4 in their STATIC per-state form over the Step_K relation: no reachable
\* state may have two conflicting Step_K-enabled successors. This invariant
\* states the DYNAMIC form over the realized history itself, the receipts this
\* verifier actually accepted: the ledger never contains two receipts consuming
\* the same (parent, key) with different successors. It is the abstract-key
\* lift of DSM_Tripwire.tla's ledger-style TripwireInvariant.
\*
\* Note it holds EVEN for a malformed key-split family at a single honest
\* verifier (DSM_GuardedMC_Fork_Ledger.cfg): once the first receipt consumes
\* the key, LinearityOK disables every conflicting candidate (paper Prop 11).
\* The malformed family's genuine danger is CROSS-verifier divergence; that
\* dynamic fork is exhibited in DSM_GuardedBilateral.tla.
\* ---------------------------------------------------------------------------
RealizedHistoryUnique ==
    \A r1, r2 \in ledger :
        (r1.parent = r2.parent /\ r1.key = r2.key) => r1.succ = r2.succ

\* ---------------------------------------------------------------------------
\* Non-vacuity: disjoint progress is permitted (paper Prop 12 /
\* DisjointProgressAllowed). The guard family admits two fulfilled candidates
\* from a common parent that consume DIFFERENT keys and reach DISTINCT
\* successors. This is NOT a fork (different keys), so realization uniqueness
\* coexists with concurrent disjoint progress — uniqueness is not achieved by
\* forbidding all concurrency. This predicate is a function of the (constant)
\* guard family only, so it holds in every reachable state when the family
\* contains such a pair.
\* ---------------------------------------------------------------------------
DisjointProgressPossible ==
    \E c1, c2 \in Candidate :
        /\ Parent(c1) = Parent(c2)
        /\ GuardOK(c1)
        /\ GuardOK(c2)
        /\ c1.key # c2.key
        /\ Successor(c1) # Successor(c2)

\* DisjointProgressAllowed, stated in the App B form over Step_K. It holds at the
\* initial (empty-consumed) state. Kept for fidelity to the paper; the always-on
\* non-vacuity check above is DisjointProgressPossible.
DisjointProgressAllowed ==
    \E s1, s2, s3 \in State : \E ka, kb \in Key :
        /\ ka # kb
        /\ StepAtKey(s1, s2, ka)
        /\ StepAtKey(s1, s3, kb)
        /\ s2 # s3

=============================================================================
