---- MODULE DSM_GuardedMC_BilateralWF ----
\* ===========================================================================
\* Relationship-scoped instance WITH an attempted same-parent conflict.
\*
\* Two relationships, rAB and rAC, deliberately reusing the same chain node
\* names h0/h1/h2. The family for rAB contains TWO conflicting candidates on
\* the same parent h0 (bid 1 -> h1, bid 4 -> h2): the attempted fork. Because
\* keys are derived from (relationship, parent) and each relationship has
\* exactly one receiver, TLC proves the attempt cannot fork in ANY
\* interleaving: the receiver realizes at most once per parent, and rAC never
\* collides with rAB despite the shared node names. Expected: No error.
\* Run:
\*   java -cp tla2tools.jar tlc2.TLC -deadlock -config DSM_GuardedMC_BilateralWF.cfg DSM_GuardedMC_BilateralWF.tla
\* ===========================================================================
EXTENDS Naturals, FiniteSets

VARIABLES cons, led

MCRel  == {"rAB", "rAC"}
MCNode == {"h0", "h1", "h2"}
MCCandidate == {
    [rel |-> "rAB", parent |-> "h0", succ |-> "h1", bid |-> 1, guard |-> TRUE],
    [rel |-> "rAB", parent |-> "h0", succ |-> "h2", bid |-> 4, guard |-> TRUE],
    [rel |-> "rAB", parent |-> "h1", succ |-> "h2", bid |-> 2, guard |-> TRUE],
    [rel |-> "rAC", parent |-> "h0", succ |-> "h1", bid |-> 3, guard |-> TRUE]
}

INSTANCE DSM_GuardedBilateral
    WITH Rel <- MCRel, Node <- MCNode, Candidate <- MCCandidate

\* Non-vacuity: the family really does contain the attempted same-parent
\* conflict that the invariants then prove harmless.
ASSUME ConflictAttemptNonVacuous ==
    \E c1, c2 \in MCCandidate :
        /\ c1.rel = c2.rel
        /\ c1.parent = c2.parent
        /\ c1.succ # c2.succ

=============================================================================
