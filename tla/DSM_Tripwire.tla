---- MODULE DSM_Tripwire ----
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS 
    Devices,
    Relationships

VARIABLES 
    deviceRoots, \* d -> revision (Nat)
    smtState,    \* d -> (rel -> tip)
    ledger       \* set of accepted receipts

Vars == <<deviceRoots, smtState, ledger>>

\* This module deliberately stops at protocol-level fork exclusion. It assumes
\* external signature and hash soundness from the post-quantum crypto layer and
\* does not attempt to model Shor-style break scenarios inside TLA.

\* =============================================================================
\* Initial State
\* =============================================================================
Init == 
    /\ deviceRoots = [d \in Devices |-> 0]
    /\ smtState = [d \in Devices |-> [r \in Relationships |-> 0]]
    /\ ledger = {}

\* =============================================================================
\* Transitions
\* =============================================================================

\* A receipt claims: "At root revision R, the state of rel was T. I transition it to T'."
ProcessReceipt(d1, d2, oldTip, newTip, r1_old, r2_old) ==
    LET 
        rel == {d1, d2}
    IN
    \* Guard 1: Root Linearity / Causal Consistency
    \* The receipt must be signed by the keys associated with the CURRENT device state.
    \* In DSM terms: You must provide a valid inclusion proof of your DevID in the global tree,
    \* and your previous op must match the verifier's known state for you.
    /\ deviceRoots[d1] = r1_old
    /\ deviceRoots[d2] = r2_old
    
    \* Guard 2: SMT Inclusion Proof Logic
    \* The receipt claims `oldTip` is the leaf for `rel` in `r1_old` and `r2_old`.
    \* In the abstract model, we check if our `smtState` (which corresponds to `r1_old`) actually has `oldTip`.
    /\ smtState[d1][rel] = oldTip
    /\ smtState[d2][rel] = oldTip
    
    \* Update State
    /\ deviceRoots' = [deviceRoots EXCEPT ![d1] = @ + 1, ![d2] = @ + 1]
    /\ smtState' = [smtState EXCEPT 
            ![d1][rel] = newTip,
            ![d2][rel] = newTip
       ]
    /\ ledger' = ledger \cup {[
            rel |-> rel, 
            oldTip |-> oldTip, 
            newTip |-> newTip,
            r1 |-> r1_old,
            r2 |-> r2_old
       ]}

\* Action: Honest participants advancing the chain
HonestStep(d1, d2) ==
    LET rel == {d1, d2}
        oldTip == smtState[d1][rel]
        newTip == oldTip + 1  \* Deterministic forward progress
        r1 == deviceRoots[d1]
        r2 == deviceRoots[d2]
    IN
        ProcessReceipt(d1, d2, oldTip, newTip, r1, r2)
        
\* Action: Adversary attempting to fork
\* Strategies:
\* 1. Replay an old tip (Double Spend)
\* 2. Fork from current tip (Race Condition)
AdversaryForkAttempt(d1, d2) ==
    LET rel == {d1, d2}
        currentTip == smtState[d1][rel]
        branchId == 999 \* A number distinct from +1
    IN
    \/  \* Strategy A: Try to fork from CURRENT tip with different content
        ProcessReceipt(d1, d2, currentTip, currentTip + branchId, deviceRoots[d1], deviceRoots[d2])
        
    \/  \* Strategy B: Try to fork from OLD tip (Rollback)
        \* This requires `oldTip < currentTip`.
        \E back \in 1..5 :
            LET rollbackTip == currentTip - back IN
            rollbackTip >= 0 /\
            ProcessReceipt(d1, d2, rollbackTip, rollbackTip + branchId, deviceRoots[d1], deviceRoots[d2])

\* =============================================================================
\* Specification
\* =============================================================================
Next ==
    \/ \E d1 \in Devices, d2 \in Devices : 
        (d1 /= d2 /\ {d1, d2} \in Relationships) /\ 
        (HonestStep(d1, d2) \/ AdversaryForkAttempt(d1, d2))

\* =============================================================================
\* Invariants
\* =============================================================================

\* The Core Tripwire Guarantee:
\* Even if the adversary tries to submit forked receipts, the combination 
\* of Causal Consistency (deviceRoots check) and SMT Inclusion (smtState check)
\* prevents any forked history from being accepted into the ledger.
TripwireInvariant == 
    \A r1, r2 \in ledger :
        (r1.rel = r2.rel /\ r1.oldTip = r2.oldTip) => (r1.newTip = r2.newTip)

\* State constraint for bounded model checking — limits counter growth
\* so TLC can exhaustively explore the reachable state space.
StateConstraint ==
    \A d \in Devices : deviceRoots[d] =< 4

Spec == Init /\ [][Next]_Vars

=============================================================================
