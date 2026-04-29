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
\* external signature and hash soundness from the post-quantum crypto layer,
\* treats bilateral countersign + Device Tree inclusion as abstract acceptance
\* guards, and does not attempt to model Shor-style break scenarios inside TLA.
\* Pending-online lock and recovery/abort mechanics live in
\* DSM_OfflineFinality.tla; this module assumes no unresolved pending online
\* projection for the relationship being advanced.
\*
\* Refinement note (whitepaper §11.1 per-step EK signing):
\* The CountersignedByBoth predicate below is satisfied in the implementation
\* by a per-step ephemeral SPHINCS+ key chain:
\*   (1) Each receipt's sig_a / sig_b is produced by a freshly-derived
\*       EK_{n+1} = SPHINCS+.KeyGen(HKDF("DSM/ek\0" || h_n || C_pre || k_step
\*                                       || K_DBRW)).
\*   (2) Each EK_{n+1} carries a cert cert_{n+1} = Sign_{SK_n}(BLAKE3(
\*       "DSM/ek-cert\0" || EK_pk_{n+1} || h_n)) chaining it back to the
\*       device's attested AK_pk via prior step keys.
\*   (3) The verifier replays the cert chain to AK_pk and verifies the
\*       receipt body against EK_pk_{n+1}.
\* Because this is a strict refinement of "abstract bilateral countersign,"
\* the Tripwire fork-exclusion theorem proven here applies unchanged. The
\* refinement is implemented in dsm_sdk::sdk::receipts::sign_receipt_with_per_step_ek
\* and verified end-to-end via per_step_signing_end_to_end_two_steps.

CountersignedByBoth(d1, d2) ==
    d1 /= d2

DeviceTreeIncluded(d) ==
    d \in Devices

ForwardAdjacent(oldTip, newTip) ==
    newTip > oldTip

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
    \* Guard 0: Acceptance scope from Whitepaper Sec. 4.1-4.3.
    \* We model bilateral countersign, device-tree inclusion, and adjacency
    \* as abstract predicates here and leave byte-exact proof validation to the
    \* implementation-side checks.
    /\ CountersignedByBoth(d1, d2)
    /\ DeviceTreeIncluded(d1)
    /\ DeviceTreeIncluded(d2)
    /\ ForwardAdjacent(oldTip, newTip)

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
            a |-> d1,
            b |-> d2,
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
\* prevents any forked history from being accepted into the ledger. This is
\* the abstract model of Whitepaper Eq. (8): no distinct accepted successor
\* may consume the same parent.
TripwireInvariant == 
    \A r1, r2 \in ledger :
        (r1.rel = r2.rel /\ r1.oldTip = r2.oldTip) => (r1.newTip = r2.newTip)

ConsumedParentUniqueness ==
    \A r1, r2 \in ledger :
        (r1.rel = r2.rel /\ r1.oldTip = r2.oldTip)
            => (r1.newTip = r2.newTip
                /\ r1.r1 = r2.r1
                /\ r1.r2 = r2.r2)

AcceptedReceiptsAdvance ==
    \A receipt \in ledger :
        receipt.newTip > receipt.oldTip

ReceiptEndpointsMatchRelation ==
    \A receipt \in ledger :
        receipt.rel = {receipt.a, receipt.b}

ReceiptChainContinuity ==
    \A receipt \in ledger :
        receipt.oldTip = 0
        \/ \E prev \in ledger :
            /\ prev.rel = receipt.rel
            /\ prev.newTip = receipt.oldTip

CurrentRelationshipAgreement ==
    \A rel \in Relationships :
        \A d1, d2 \in rel :
            smtState[d1][rel] = smtState[d2][rel]

CurrentTipsWereAccepted ==
    \A d \in Devices, rel \in Relationships :
        (d \in rel /\ smtState[d][rel] # 0)
            => \E receipt \in ledger :
                /\ receipt.rel = rel
                /\ receipt.newTip = smtState[d][rel]

FirstContactBinding ==
    \A r1, r2 \in ledger :
        (r1.rel = r2.rel /\ r1.oldTip = 0 /\ r2.oldTip = 0)
            => r1.newTip = r2.newTip

\* State constraint for bounded model checking — limits counter growth
\* so TLC can exhaustively explore the reachable state space.
StateConstraint ==
    \A d \in Devices : deviceRoots[d] =< 4

Spec == Init /\ [][Next]_Vars

=============================================================================
