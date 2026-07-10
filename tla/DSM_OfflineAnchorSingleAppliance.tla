---- MODULE DSM_OfflineAnchorSingleAppliance ----
EXTENDS Naturals, FiniteSets, TLC

\* =============================================================================
\* DSM offline-bearer appliance — single-appliance anchor-origin uniqueness.
\*
\* v2 ("Software Authority, Hardware Identity", July 2026). This module models
\* ONE correct enrolled offline-bearer appliance and proves DIRECTLY that it
\* cannot originate two valid releases from a single SMT anchor origin
\* (R_i, h_i, u_i). Not "they collide later", not "detected on reconciliation":
\* it simply cannot happen inside the modeled appliance state machine.
\*
\* Relationship to the guarded kernel (paper: DSM as Guarded Linear Constraint
\* Systems): this is the OFFLINE-ANCHOR special case, exactly as DSM_Tripwire.tla
\* is the bilateral-tip special case. The abstract resource-consumption key of
\* DSM_Guarded.tla / lean4/DSMGuardedTripwire.lean is instantiated here by the
\* anchor origin (R_i, h_i, u_i): device SMT root R_i as the parent, the offline
\* frontier h_i and the committed SMT anchor counter u_i as the descriptor. The
\* universal proof is lean4/DSMOfflineAnchorOrigin.lean; this module model-checks
\* the concrete appliance instance.
\*
\* It supersedes the receiver-witnessed counter-positioned commit: no FROM/TO
\* counter read, no MACANDD witness, no fused anchor head, no boot ticket. The
\* physical counter H is a non-rewind FLOOR synchronized one-to-one to the SMT
\* counter (u = H0 - H), not an acceptance authority.
\* =============================================================================

CONSTANTS
    H0,        \* enrolled TROPIC01 physical counter value
    Content    \* the transition digests D_{i+1} an appliance/host may propose

VARIABLES
    root,             \* R_i : device SMT root
    frontier,         \* h_i : offline frontier root
    smtCounter,       \* u_i : SMT anchor counter (committed leaf coordinate)
    physH,            \* H   : live raw TROPIC01 counter (counts DOWN)
    status,           \* {"Ready","Prepared","Committed"}
    prepared,         \* the single prepared record, or NoRec
    committed,        \* the committed record, or NoRec
    committedLedger,  \* set of ALL committed records ever (history)
    consumedOrigins,  \* set of anchor origins a commit has consumed
    emitted           \* set of emitted release packages

Vars == <<root, frontier, smtCounter, physH, status,
          prepared, committed, committedLedger, consumedOrigins, emitted>>

NoRec == "NONE"

Origin(r, h, u) == [r |-> r, h |-> h, u |-> u]

\* Forward-only successor advances (h_{i+1}, R_{i+1}) as PURE functions of the
\* origin plus the transition digest `content` (D_{i+1}). Distinct content yields
\* a distinct successor, so a fork is CONSTRUCTIBLE in principle; the appliance
\* state machine is what excludes it. u_{i+1} = u_i + 1 always.
NextFrontier(h, content) == (h * 8) + content
NextRoot(r, h, u, content) == (r * 100) + (h * 10) + u + (content * 1000)

MkRecord(r, h, u, content) ==
    [ originR |-> r, originH |-> h, originU |-> u,
      content |-> content,
      nextU   |-> u + 1,
      nextH   |-> NextFrontier(h, content),
      nextR   |-> NextRoot(r, h, u, content) ]

RecOrigin(rec) == Origin(rec.originR, rec.originH, rec.originU)

Init ==
    /\ root = 0
    /\ frontier = 0
    /\ smtCounter = 0
    /\ physH = H0
    /\ status = "Ready"
    /\ prepared = NoRec
    /\ committed = NoRec
    /\ committedLedger = {}
    /\ consumedOrigins = {}
    /\ emitted = {}

\* =============================================================================
\* Honest appliance cycle: Prepare -> Commit -> Emit -> Finalize (+ Recover)
\* =============================================================================

\* PREPARE (paper 13.1): form the cross-bound record over the CURRENT origin.
\* No counter moves. Guarded on Ready, counter synchronization at the origin
\* (u_i = H0 - H), the origin not already consumed, and one prepared record only.
Prepare(content) ==
    /\ status = "Ready"
    /\ smtCounter = H0 - physH
    /\ Origin(root, frontier, smtCounter) \notin consumedOrigins
    /\ prepared' = MkRecord(root, frontier, smtCounter, content)
    /\ status' = "Prepared"
    /\ UNCHANGED <<root, frontier, smtCounter, physH,
                   committed, committedLedger, consumedOrigins, emitted>>

\* COMMIT (paper 13.2): re-pin H0 - H = u_i, move the physical counter by exactly
\* one, mark the origin consumed. Point of no return.
Commit ==
    /\ status = "Prepared"
    /\ physH > 0
    /\ prepared.originU = H0 - physH               \* re-pin (checked arithmetic)
    /\ RecOrigin(prepared) \notin consumedOrigins   \* linearity: one commit / origin
    /\ physH' = physH - 1
    /\ committed' = prepared
    /\ committedLedger' = committedLedger \cup {prepared}
    /\ consumedOrigins' = consumedOrigins \cup {RecOrigin(prepared)}
    /\ status' = "Committed"
    /\ UNCHANGED <<root, frontier, smtCounter, prepared, emitted>>

\* EMIT (paper 13.3): export the committed package.
Emit ==
    /\ status = "Committed"
    /\ emitted' = emitted \cup {committed}
    /\ UNCHANGED <<root, frontier, smtCounter, physH, status,
                   prepared, committed, committedLedger, consumedOrigins>>

\* FINALIZE (paper 13.3): advance the active state to the successor; back to Ready.
Finalize ==
    /\ status = "Committed"
    /\ root' = committed.nextR
    /\ frontier' = committed.nextH
    /\ smtCounter' = committed.nextU
    /\ status' = "Ready"
    /\ prepared' = NoRec
    /\ committed' = NoRec
    /\ UNCHANGED <<physH, committedLedger, consumedOrigins, emitted>>

\* RECOVER (paper 15): re-emit the SAME committed package. Idempotent set union,
\* so recovery can never introduce a DIFFERENT package for the same counter step.
Recover ==
    /\ status = "Committed"
    /\ emitted' = emitted \cup {committed}
    /\ UNCHANGED <<root, frontier, smtCounter, physH, status,
                   prepared, committed, committedLedger, consumedOrigins>>

\* =============================================================================
\* Adversary / host attempts against the appliance (must be guarded out)
\* =============================================================================

\* Attempt a SECOND prepare from an already-consumed origin. The physical counter
\* has advanced past it, so the re-pin `o.u = H0 - physH` cannot hold: not enabled.
AttemptSecondPrepareSameOrigin ==
    /\ status = "Ready"
    /\ \E o \in consumedOrigins, content \in Content :
        /\ o.u = H0 - physH
        /\ prepared' = MkRecord(o.r, o.h, o.u, content)
        /\ status' = "Prepared"
    /\ UNCHANGED <<root, frontier, smtCounter, physH,
                   committed, committedLedger, consumedOrigins, emitted>>

\* Attempt a SECOND commit against an already-consumed origin (any content, e.g.
\* a different transition digest to fork the successor). Blocked by BOTH the
\* re-pin and the linearity guard: not enabled.
AttemptSecondCommitSameOrigin ==
    /\ \E o \in consumedOrigins, content \in Content :
        LET rec == MkRecord(o.r, o.h, o.u, content) IN
        /\ physH > 0
        /\ o.u = H0 - physH
        /\ RecOrigin(rec) \notin consumedOrigins
        /\ physH' = physH - 1
        /\ committed' = rec
        /\ committedLedger' = committedLedger \cup {rec}
        /\ consumedOrigins' = consumedOrigins \cup {RecOrigin(rec)}
        /\ status' = "Committed"
    /\ UNCHANGED <<root, frontier, smtCounter, prepared, emitted>>

\* POWER LOSS before commit: drop the prepared record, return to Ready. No
\* counter moved, so the origin is NOT consumed and may be honestly re-prepared.
PowerLossBeforeCommit ==
    /\ status = "Prepared"
    /\ status' = "Ready"
    /\ prepared' = NoRec
    /\ UNCHANGED <<root, frontier, smtCounter, physH,
                   committed, committedLedger, consumedOrigins, emitted>>

Next ==
    \/ \E c \in Content : Prepare(c)
    \/ Commit
    \/ Emit
    \/ Finalize
    \/ Recover
    \/ AttemptSecondPrepareSameOrigin
    \/ AttemptSecondCommitSameOrigin
    \/ PowerLossBeforeCommit

\* =============================================================================
\* Invariants
\* =============================================================================

SameOrigin(p, q) ==
    /\ p.originR = q.originR
    /\ p.originH = q.originH
    /\ p.originU = q.originU

\* THE claim: one appliance never emits two distinct releases from one origin.
NoTwoEmittedSameOrigin ==
    \A p, q \in emitted : SameOrigin(p, q) => p = q

\* One committed record per anchor origin, over all history.
NoTwoCommittedSameOrigin ==
    \A p, q \in committedLedger : SameOrigin(p, q) => p = q

\* The physical counter is synchronized to the SMT counter whenever Ready.
CounterSync ==
    (status = "Ready") => (smtCounter = H0 - physH)

\* Commit from (R_i, h_i, u_i) produces only u_{i+1} = u_i + 1.
CommitAdvancesOrigin ==
    \A p \in committedLedger : p.nextU = p.originU + 1

\* Once committed, the origin is consumed; the Prepare/Commit guards then forbid
\* any second use of that same (R_i, h_i, u_i).
SecondSameOriginFails ==
    \A p \in committedLedger : RecOrigin(p) \in consumedOrigins

\* Recovery re-emits an existing committed record; it never signs a different
\* package for the same counter step.
RecoveryIdempotence ==
    \A p \in emitted : p \in committedLedger

\* State constraint for bounded model checking.
StateConstraint ==
    smtCounter =< H0

Spec == Init /\ [][Next]_Vars

=============================================================================
