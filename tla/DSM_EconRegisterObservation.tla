---- MODULE DSM_EconRegisterObservation ----
EXTENDS Naturals, FiniteSets, TLC

\* =============================================================================
\* THE ECONOMIC REGISTER, OBSERVED CONCURRENTLY.
\*
\* SCOPE. A write-once economic register cell is replicated across the member
\* set a vault's own signed state committed. This module models what a READER
\* is entitled to conclude while claimants are concurrently writing, members
\* are failing, and members are REBUILDING their registers -- and what the
\* caller of that reader is entitled to do with the answer.
\*
\* This owns the BEHAVIOURAL half of the frozen semantics only. The ALGEBRAIC
\* half -- that the canonical quorum is the strict majority, and that 2q > n
\* forces any two qualifying quorums to intersect -- is a universal statement
\* over all n and belongs to Lean (lean4/DSMEconomicSmtSeparation.lean, §10).
\* Nothing below re-derives it: Quorum is a CONSTANT supplied by the caller,
\* exactly as observe_cell takes it as an argument, and there is deliberately
\* NO operator computing a quorum from Cardinality(Member). A local
\* majority-of-catalog rule is the verifier's opinion, not the vault's.
\*
\* What TLC uniquely buys is the ROUND: what can happen to the register between
\* the sample of one member and the sample of the next, and what a reader may
\* conclude across a sequence of rounds. observe_cell applied to one fixed list
\* of reads is a pure function and is Lean's business.
\*
\* AMENDMENT ANCHORING
\*   docs/papers/amendment-2c-c2-verification-substrate.md
\*     Ruling B  0x0002 went to schema 3 so each member is paired with its
\*               register_incarnation_id, because "a rebuilt member is a
\*               DIFFERENT entry". CommittedInc below IS that pairing.
\*     Ruling C  fail closed for ACTION does not mean classify as INVALID.
\*
\* CODE TRACEABILITY
\*   dsm/src/economic/cell_observation.rs:41-49    MemberCellRead
\*   dsm/src/economic/cell_observation.rs:52-65    CellObservation
\*   dsm/src/economic/cell_observation.rs:122-142  tally first, select nothing
\*   dsm/src/economic/cell_observation.rs:143-175  resolution order
\*   dsm_sdk/src/sdk/storage_node_sdk.rs:663-669   answer_counts_for: BOTH
\*                                                 echo halves are normative
\*   dsm_sdk/src/sdk/storage_node_sdk.rs:1072-1082 an absence must be ASSERTED
\*   dsm_sdk/src/sdk/economic_registers.rs:232     MODELLED DEFECT
\*   dsm/src/economic/peer_lineage.rs:165-169      MODELLED DEFECT
\* =============================================================================

CONSTANTS
    Member,                         \* member ids the vault's state COMMITTED
    Cell,                           \* write-once cells in scope
    Value,                          \* distinct byte-strings claimants may write
    Wire,                           \* wire-answer alphabet for this cfg
    Quorum,                         \* q, SUPPLIED by the vault's committed state
    MaxRebuild,                     \* rebuilds per member (bounds state)
    MaxRounds,                      \* completed read rounds (bounds state)
    MaxStep,                        \* DFID depth budget; see ASSUME
    AttributionRequiresIncarnation, \* [TRUE]  answer_counts_for, BOTH halves
    UnusableCountsAsAbsent,         \* [FALSE] "an error is evidence of emptiness"
    ObserverPicksFirstAtQuorum,     \* [FALSE] resolve two-at-quorum by iteration order
    MemberKeepsWriteOnce,           \* [TRUE]  insert-if-absent, no update path
    ConsumerDiscipline              \* ["FailClosed"] see Verdict

NONE == "NONE"

\* The incarnation each member was COMMITTED at: the second half of every
\* schema-3 (member_id, register_incarnation_id) pair.
CommittedInc == [m \in Member |-> 0]

\* The verifier's OWN opinion of q. Used ONLY in the ASSUME -- never in the
\* transition relation. This is the structural statement that the vault
\* supplies q and the verifier does not.
LocalMajority == (Cardinality(Member) \div 2) + 1

ASSUME QuorumIsPositive == Quorum > 0

VARIABLES
    cellVal,       \* [Member -> [Cell -> Value \cup {NONE}]]
    inc,           \* [Member -> Nat] live register incarnation
    target,        \* Cell : the cell this round asks about
    sample,        \* [Member -> {"unsampled"} \cup Wire]
    claimedSoFar,  \* [Cell -> Value \cup {NONE}] every value ever Claimed
    lastObs,       \* the observation the last completed round produced
    lastVerdict,   \* what the consumer did with it
    lastTrueAbsent,\* ground-truth attributable absences that round
    rounds

Vars == <<cellVal, inc, target, sample, claimedSoFar,
          lastObs, lastVerdict, lastTrueAbsent, rounds>>

\* =============================================================================
\* ATTRIBUTION. An answer this observer could not attribute to the member it
\* ASKED is Unavailable. Two halves: the node id, and the register incarnation.
\* A member that rebuilt its register still answers with its own id.
\* =============================================================================
Attributable(m) ==
    /\ sample[m] # "Misattributed"
    /\ (AttributionRequiresIncarnation => inc[m] = CommittedInc[m])

\* GROUND TRUTH attribution: the incarnation requirement is hard-coded and is
\* NOT flag-controlled. The invariants compare the observer's numbers against
\* these, and that comparison is what makes a mutation detectable.
TrulyAttributable(m) ==
    /\ sample[m] # "Misattributed"
    /\ inc[m] = CommittedInc[m]

\* =============================================================================
\* CLASSIFICATION. Only an explicit success and an explicit, ASSERTED absence
\* are answers. Timeout, transport error, 5xx, a 404 that did not assert
\* absence, and any unattributable response are Unavailable.
\* =============================================================================
Classify(m) ==
    IF ~Attributable(m)            THEN "Unavailable"
    ELSE IF sample[m] = "Value"    THEN "Value"
    ELSE IF sample[m] = "Absent"   THEN "Absent"
    ELSE IF UnusableCountsAsAbsent THEN "Absent"   \* <== THE HISTORICAL DEFECT
    ELSE "Unavailable"

\* =============================================================================
\* THE TALLY. Everything is counted FIRST; nothing is selected here.
\* =============================================================================
ValueCount(v)   == Cardinality({m \in Member : Classify(m) = "Value" /\ cellVal[m][target] = v})
AbsentCount     == Cardinality({m \in Member : Classify(m) = "Absent"})
Seen            == {v \in Value : ValueCount(v) > 0}
AtQuorum        == {v \in Value : ValueCount(v) >= Quorum}
TrueAbsentCount == Cardinality({m \in Member : TrulyAttributable(m) /\ sample[m] = "Absent"})

\* =============================================================================
\* ONLY NOW IS ANYTHING CHOSEN.
\* =============================================================================
Observation ==
    IF Cardinality(AtQuorum) = 1
      THEN [kind |-> "Claimed", value |-> CHOOSE v \in AtQuorum : TRUE, cell |-> target]
    ELSE IF Cardinality(AtQuorum) > 1
      \* Two values at quorum is arithmetically impossible while q is a strict
      \* majority, and is exactly what a noncanonical q produces. REFUSED, not
      \* resolved by iteration order.
      THEN IF ObserverPicksFirstAtQuorum
             THEN [kind |-> "Claimed", value |-> CHOOSE v \in AtQuorum : TRUE, cell |-> target]
             ELSE [kind |-> "Conflict", value |-> NONE, cell |-> target]
    ELSE IF Cardinality(Seen) > 1
      \* Contradictory claims and no winner. A minority disagreement BESIDE a
      \* quorum winner is not this case: cells are write-once, so the loser can
      \* never gain a majority. A,A,B at q=2 resolved above.
      THEN [kind |-> "Conflict", value |-> NONE, cell |-> target]
    ELSE IF AbsentCount >= Quorum
      THEN [kind |-> "EmptyAtQuorum", value |-> NONE, cell |-> target]
    ELSE [kind |-> "Unavailable", value |-> NONE, cell |-> target]

\* =============================================================================
\* THE CONSUMER. "Empty" is the model's name for Option::None at the Rust call
\* site: EmptyAtQuorum and Ok(None) are the SAME downstream fact, and that
\* indistinguishability IS the defect.
\* =============================================================================
Verdict(o) ==
    CASE ConsumerDiscipline = "FailClosed" ->
            CASE o.kind = "Claimed"       -> "Winner"
              [] o.kind = "EmptyAtQuorum" -> "Empty"
              [] OTHER                    -> "Refused"
      \* economic_registers.rs:232 -- an unusable read delivered as emptiness.
      [] ConsumerDiscipline = "UnavailableIsNone" ->
            CASE o.kind = "Claimed"  -> "Winner"
              [] o.kind = "Conflict" -> "Refused"
              [] OTHER               -> "Empty"
      \* peer_lineage.rs:165-169 -- .ok().flatten(): a quarantined write-once
      \* cell delivered as emptiness.
      [] ConsumerDiscipline = "AllNonWinnersAreNone" ->
            CASE o.kind = "Claimed" -> "Winner"
              [] OTHER              -> "Empty"

NoObs == [kind |-> NONE, value |-> NONE, cell |-> CHOOSE c \in Cell : TRUE]

Init ==
    /\ cellVal        = [m \in Member |-> [c \in Cell |-> NONE]]
    /\ inc            = CommittedInc
    /\ target         \in Cell
    /\ sample         = [m \in Member |-> "unsampled"]
    /\ claimedSoFar   = [c \in Cell |-> NONE]
    /\ lastObs        = NoObs
    /\ lastVerdict    = NONE
    /\ lastTrueAbsent = 0
    /\ rounds         = 0

\* CLAIM: a claimant's write-once insert reaches member m. Insert-if-absent.
\* Two claimants racing for one cell is the honest, shipped source of a
\* Conflict: different members accept different claimants.
Claim(m, c, v) ==
    /\ MemberKeepsWriteOnce => cellVal[m][c] = NONE
    /\ cellVal' = [cellVal EXCEPT ![m][c] = v]
    /\ UNCHANGED <<inc, target, sample, claimedSoFar,
                   lastObs, lastVerdict, lastTrueAbsent, rounds>>

\* REBUILD: the member rebuilt its register. Its incarnation moves off the one
\* the vault committed and its rows are gone. It still answers with its own
\* node id, which is why identity alone cannot exclude it. May happen MID-ROUND.
Rebuild(m) ==
    /\ inc[m] < CommittedInc[m] + MaxRebuild
    /\ inc'     = [inc     EXCEPT ![m] = inc[m] + 1]
    /\ cellVal' = [cellVal EXCEPT ![m] = [c \in Cell |-> NONE]]
    /\ UNCHANGED <<target, sample, claimedSoFar,
                   lastObs, lastVerdict, lastTrueAbsent, rounds>>

\* SAMPLE: capture one member's answer NOW. THIS is the concurrency point: a
\* Claim or a Rebuild may interleave between any two samples of one round.
\* Members are honest-but-faulty: a member asserts an absence only when it has
\* one. Forgery is a signature question and is outside this abstraction.
Sample(m, w) ==
    /\ sample[m] = "unsampled"
    /\ (w = "Value"  => cellVal[m][target] # NONE)
    /\ (w = "Absent" => cellVal[m][target] = NONE)
    /\ sample' = [sample EXCEPT ![m] = w]
    /\ UNCHANGED <<cellVal, inc, target, claimedSoFar,
                   lastObs, lastVerdict, lastTrueAbsent, rounds>>

\* RESOLVE: the round is complete. Tally and selection are a pure local
\* computation over answers already captured -- not a concurrency point.
Resolve ==
    /\ \A m \in Member : sample[m] # "unsampled"
    /\ LET o == Observation IN
        /\ lastObs'        = o
        /\ lastVerdict'    = Verdict(o)
        /\ lastTrueAbsent' = TrueAbsentCount
        /\ claimedSoFar'   = IF o.kind = "Claimed"
                               THEN [claimedSoFar EXCEPT ![target] = o.value]
                               ELSE claimedSoFar
    /\ sample' = [m \in Member |-> "unsampled"]
    /\ rounds' = rounds + 1
    /\ target' \in Cell
    /\ UNCHANGED <<cellVal, inc>>

Next ==
    \/ \E m \in Member, c \in Cell, v \in Value : Claim(m, c, v)
    \/ \E m \in Member : Rebuild(m)
    \/ \E m \in Member, w \in Wire : Sample(m, w)
    \/ Resolve

Spec == Init /\ [][Next]_Vars

\* =============================================================================
\* INVARIANTS
\* =============================================================================

TypeOK ==
    /\ inc         \in [Member -> Nat]
    /\ target      \in Cell
    /\ rounds      \in Nat
    /\ lastVerdict \in {"Winner", "Empty", "Refused", NONE}

\* ---------------------------------------------------------------------------
\* SAFETY 1: failure / incompleteness / unavailable quorum MUST NEVER collapse
\*           to empty.
\* ---------------------------------------------------------------------------

\* The caller's emptiness fact is grounded in the observation layer's emptiness
\* arm and nothing else. Refusal is not emptiness. This is what .ok().flatten()
\* violates.
EmptinessIsGrounded ==
    lastVerdict = "Empty" => lastObs.kind = "EmptyAtQuorum"

\* ...and that arm is grounded in a quorum of EXPLICIT, attributable absences
\* counted from GROUND TRUTH, never from the classifier whose leniency is the
\* thing under test. This is what "an error is evidence of emptiness" violates.
EmptyAtQuorumIsWitnessed ==
    lastObs.kind = "EmptyAtQuorum" => lastTrueAbsent >= Quorum

\* THE CROSS-ROUND FORM, and the one only TLC can state. A cell observed
\* Claimed is never later observed empty -- across every interleaving of
\* concurrent claims, outages and register rebuilds.
NoEmptyAtQuorumAfterClaimed ==
    lastObs.kind = "EmptyAtQuorum" => claimedSoFar[lastObs.cell] = NONE

\* ---------------------------------------------------------------------------
\* SAFETY 2: conflicting qualifying observations MUST NOT be resolved by local
\*           tie-breaking into a valid winner.
\* ---------------------------------------------------------------------------

TwoAtQuorumIsConflict ==
    (rounds > 0 /\ Cardinality(AtQuorum) > 1) => lastObs.kind # "Claimed"

\* The consumer's verdict is a TOTAL FUNCTION of the four-valued observation.
\* No third input -- not iteration order, not a retry count, not a local catalog
\* opinion -- may enter. Forbids every tie-break at the consumer and every
\* collapse of a refusal into emptiness.
VerdictMatchesObservation ==
    /\ lastObs.kind = "Claimed"       => lastVerdict = "Winner"
    /\ lastObs.kind = "EmptyAtQuorum" => lastVerdict = "Empty"
    /\ lastObs.kind = "Conflict"      => lastVerdict = "Refused"
    /\ lastObs.kind = "Unavailable"   => lastVerdict = "Refused"

\* ---------------------------------------------------------------------------
\* NON-VACUITY, NEGATED. Listed only in the *_Reachability cfg, which is
\* EXPECTED TO FAIL: the counterexample trace IS the witness. Without it, a
\* falsification config could pass for the wrong reason -- Conflict never
\* reachable at all.
\* ---------------------------------------------------------------------------
ConflictUnreachable == lastObs.kind # "Conflict"

\* =============================================================================
\* STATE CONSTRAINT (TLC finiteness)
\* =============================================================================
StateConstraint ==
    /\ rounds =< MaxRounds
    /\ \A m \in Member : inc[m] =< CommittedInc[m] + MaxRebuild

====
