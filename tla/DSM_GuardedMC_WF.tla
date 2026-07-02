---- MODULE DSM_GuardedMC_WF ----
\* ===========================================================================
\* Model-check instance for DSM_Guarded — WELL-FORMED guard family.
\*
\* A real conflict class {bid 1, bid 2} at key "k1" that resolves to the SAME
\* successor "s1" (G5/G7 well formed), plus a disjoint branch (bid 3) at key
\* "k2". Safety and DisjointProgressPossible both hold, and the realized
\* history (ledger) never contains two receipts consuming the same
\* (parent, key) with different successors (RealizedHistoryUnique).
\*
\* Model values are encoded as strings, so no .cfg record literals are needed
\* (TLC's .cfg grammar does not accept record expressions in CONSTANT
\* assignments). Run:
\*   java -cp tla2tools.jar tlc2.TLC -config DSM_GuardedMC_WF.cfg DSM_GuardedMC_WF.tla
\* ===========================================================================
EXTENDS Naturals, FiniteSets

VARIABLES current, consumed, realized, pending, ledger

MCState == {"s0", "s1", "s2"}
MCKey   == {"k1", "k2"}
MCCandidate == {
    [parent |-> "s0", succ |-> "s1", key |-> "k1", bid |-> 1, guard |-> TRUE],
    [parent |-> "s0", succ |-> "s1", key |-> "k1", bid |-> 2, guard |-> TRUE],
    [parent |-> "s0", succ |-> "s2", key |-> "k2", bid |-> 3, guard |-> TRUE]
}

INSTANCE DSM_Guarded
    WITH State <- MCState, Key <- MCKey, Candidate <- MCCandidate

\* Non-vacuity (paper Prop 12 / DisjointProgressAllowed): the well-formed guard
\* family genuinely admits disjoint concurrent progress. Asserted as a named
\* constant-level assumption (TLC's recommended form for variable-free facts), so
\* uniqueness is demonstrably NOT achieved by forbidding all concurrency.
ASSUME DisjointProgressNonVacuous == DisjointProgressPossible

=============================================================================
