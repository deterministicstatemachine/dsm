---- MODULE DSM_GuardedMC_BilateralFork ----
\* ===========================================================================
\* STRUCTURE-REMOVED contrast model. This configuration is UNCONSTRUCTIBLE in
\* online DSM; it exists to show which structure is load bearing.
\*
\* What this model deletes, relative to DSM:
\*   (1) Derived keys (paper Rule 2, Def 27/33). Here `key` is a FREE field a
\*       candidate simply carries, so two candidates can share a key while
\*       claiming different successors. In DSM the key is derived from the
\*       committed (relationship, parent): every relationship is its own
\*       straight hash chain and a parent under one relationship is not
\*       replayable under another (paper Sec 6).
\*   (2) The bilateral single-receiver topology. Here TWO independent
\*       receivers each accept candidates for the same parent. Online DSM has
\*       no such thing: a relationship step has exactly one receiver, the
\*       counterparty of that relationship. Presenting one spendable object
\*       to multiple distinct receivers exists only in offline bearer mode,
\*       which is governed by the fused anchor, the Def 56 pending lock, the
\*       offline anchor design's co-signed precommit, and reconciliation
\*       (paper Sec 29, Thm 14). That is a different mechanism with its own
\*       model and is out of scope here.
\*
\* With both deletions, TLC finds the fork: receiver A realizes s1 and
\* receiver B realizes s2 for the same (parent, key). Expected:
\* "Invariant CrossVerifierAgreement is violated" with a multi-step trace.
\* Each receiver alone still stays locally linear (RealizedHistoryUniqueLocal
\* holds): the divergence needs BOTH deletions plus multiple receivers.
\* DSM_GuardedMC_BilateralWF.tla proves the same conflict attempt cannot fork
\* once the real structure is present.
\* Run:
\*   java -cp tla2tools.jar tlc2.TLC -deadlock -config DSM_GuardedMC_BilateralFork.cfg DSM_GuardedMC_BilateralFork.tla
\* ===========================================================================
EXTENDS Naturals, FiniteSets

VARIABLES curA, consumedA, ledgerA, curB, consumedB, ledgerB

Vars == <<curA, consumedA, ledgerA, curB, consumedB, ledgerB>>

MCState == {"s0", "s1", "s2"}
MCKey   == {"k1", "k2"}
\* Free-key candidates: the key-split family. NOT expressible with derived keys.
MCCandidate == {
    [parent |-> "s0", succ |-> "s1", key |-> "k1", bid |-> 1, guard |-> TRUE],
    [parent |-> "s0", succ |-> "s2", key |-> "k1", bid |-> 4, guard |-> TRUE]
}

Receipt(c) == [parent |-> c.parent, key |-> c.key, succ |-> c.succ, bid |-> c.bid]

StepOK(cur, cons, c) ==
    /\ c \in MCCandidate
    /\ c.guard = TRUE
    /\ c.parent = cur
    /\ c.key \notin cons

RealizeA(c) ==
    /\ StepOK(curA, consumedA, c)
    /\ curA'      = c.succ
    /\ consumedA' = consumedA \cup {c.key}
    /\ ledgerA'   = ledgerA \cup {Receipt(c)}
    /\ UNCHANGED <<curB, consumedB, ledgerB>>

RealizeB(c) ==
    /\ StepOK(curB, consumedB, c)
    /\ curB'      = c.succ
    /\ consumedB' = consumedB \cup {c.key}
    /\ ledgerB'   = ledgerB \cup {Receipt(c)}
    /\ UNCHANGED <<curA, consumedA, ledgerA>>

Init ==
    /\ curA \in MCState
    /\ curB = curA
    /\ consumedA = {}
    /\ consumedB = {}
    /\ ledgerA = {}
    /\ ledgerB = {}

Next == \E c \in MCCandidate : RealizeA(c) \/ RealizeB(c)

Spec == Init /\ [][Next]_Vars

TypeOK ==
    /\ curA \in MCState
    /\ curB \in MCState
    /\ consumedA \subseteq MCKey
    /\ consumedB \subseteq MCKey
    /\ ledgerA \subseteq [parent : MCState, key : MCKey, succ : MCState, bid : Nat]
    /\ ledgerB \subseteq [parent : MCState, key : MCKey, succ : MCState, bid : Nat]

RealizedHistoryUniqueLocal ==
    /\ \A r1, r2 \in ledgerA :
          (r1.parent = r2.parent /\ r1.key = r2.key) => r1.succ = r2.succ
    /\ \A r1, r2 \in ledgerB :
          (r1.parent = r2.parent /\ r1.key = r2.key) => r1.succ = r2.succ

CrossVerifierAgreement ==
    \A ra \in ledgerA, rb \in ledgerB :
        (ra.parent = rb.parent /\ ra.key = rb.key) => ra.succ = rb.succ

=============================================================================
