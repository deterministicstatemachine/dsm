---- MODULE DSM_SofiSuccessorCells ----
EXTENDS Naturals, FiniteSets, TLC

\* =============================================================================
\* SOFI V8 SUCCESSOR CELLS, AT THE MEMBERS.
\*
\* SCOPE. One DLV parent's attempt chain (keys K^(0), K^(1)) and the two trader
\* positions whose registered fulfillments may write into it, replicated across
\* the frozen five-member set (plan revision 10.3, F0, F2's registers, F4, F5,
\* F7). This module owns what happens at the MEMBERS while writers, verifiers
\* and faults interleave: one member at a time accepts a write, a verifier reads
\* some members and not others and may write a Dead record, relayers publish
\* fulfillments, validation evidence arrives late, and the walk classifies each
\* key and consumes the parent.
\*
\* A register is a vector of per-value holder COUNTS over the members. Under
\* crash-omission a member that never answers is one that never wrote, so the
\* counts are exact for every question asked here; member identity is not.
\* A count stops at the finality threshold: a further holder of a value that is
\* already final changes no property below, and the state space stays small
\* enough for the gate.
\* The universal quorum algebra -- 3 + 3 > 5, write-once, Dead soundness on a
\* partial read -- is Lean's (lean4/DSMSofiSuccessorCells.lean) and is not
\* re-derived. What the operation does with these facts -- routes, outcomes,
\* resolution, the fence -- is DSM_SofiFulfillment.tla.
\*
\* THE MODEL
\*   one parent, attempts 0 and 1
\*   T   signs FT0 (E1, attempt 0) only; FT1 would be a FORGED attempt vector
\*   U   signs FU0 and FU1 (E2, attempts 0 and 1): two exercises of one position
\*   W   signs FW0 (E3, attempt 0): a third writer, so votes can split Dead;
\*       W's operation is Invalid, so its final is objectively skipped
\*   a verifier observes any subset of the members and may record Dead
\*
\* FALSIFICATIONS. Each DSM_SofiSuccessorCells_<Name>.cfg flips one constant below
\* (or states a claim that must be false) and lists exactly the invariant it
\* must violate; tools/vertical_validation/src/tla_runner.rs gates the verdict
\* and tla/README.md tabulates them.
\* =============================================================================

CONSTANTS
    N,                         \* members in the frozen set (5)
    ValidE2,                   \* [TRUE] RouteValidation of U's operation
    MaxStep,                   \* DFID depth budget (runner reads it)
    OverwriteAllowed,          \* [FALSE] a member replaces its cell value
    PermanentStoreLoss,        \* [FALSE] a member loses a stored cell
    EquivocatingMember,        \* [FALSE] one member answers two values
    QuorumTwo,                 \* [FALSE] finality at two cells
    UnreadDroppedFromCount,    \* [FALSE] an unread member counts toward nothing
    TimeoutRecordsDead,        \* [FALSE] a timed-out read is recorded Dead
    NumericHole,               \* [FALSE] attempt 1 without attempt 0 resolved
    AttemptLiveOmitted,        \* [FALSE] consumption without AttemptLive
    CellsBeforeFulfillment,    \* [FALSE] cell ingress without a registered F
    FulfillmentSpray,          \* [FALSE] a registered F writes another attempt's key
    RelayWithoutKeyBinding,    \* [FALSE] F ingress without the precommit's key
    UnavailableAsInvalid,      \* [FALSE] missing evidence rejects a final
    InvalidFinalNotSkipped     \* [FALSE] an Invalid final is not skipped

ASSUME N = 5 /\ MaxStep \in Nat

Finality == IF QuorumTwo THEN 2 ELSE 3
Capacity == IF EquivocatingMember THEN N + 1 ELSE N

T == "T"
U == "U"
W == "W"
Traders == {T, U, W}
E1 == "E1"
E2 == "E2"
E3 == "E3"
Values == {E1, E2, E3}
Attempts == {0, 1}

\* A fulfillment: its trader, its E and its attempt at this parent.
FT0 == <<T, 0>>
FT1 == <<T, 1>>
FU0 == <<U, 0>>
FU1 == <<U, 1>>
FW0 == <<W, 0>>
Options(tr) == {<<tr, 0>>, <<tr, 1>>}
Fulfillments == Options(T) \cup Options(U) \cup Options(W)
TraderOf(f) == f[1]
AttemptOf(f) == f[2]
EOfTrader(tr) == CASE tr = T -> E1 [] tr = U -> E2 [] OTHER -> E3
EOf(f) == EOfTrader(TraderOf(f))
Signed == {FT0, FU0, FU1, FW0}
TruthOf(e) == CASE e = E2 -> ValidE2 [] e = E3 -> FALSE [] OTHER -> TRUE

VARIABLES
    reg,        \* [Fulfillments -> holders at its trader's K_ful(q)]
    cell,       \* [Attempts -> [Values -> holders]]
    deadRec,    \* keys with a Dead resolution record
    evid,       \* E values whose validation evidence is available
    everFinal,  \* [Attempts -> values ever final at that key]
    everReg,    \* [Traders -> fulfillments ever registered at the position]
    consHist    \* E values ever observed consuming the parent

vars == <<reg, cell, deadRec, evid, everFinal, everReg, consHist>>

SumReg(tr) == reg[<<tr, 0>>] + reg[<<tr, 1>>]
SumCell(a) == cell[a][E1] + cell[a][E2] + cell[a][E3]

Registered(f) == reg[f] >= Finality
Final(a, v) == cell[a][v] >= Finality
FinalValues(a) == {v \in Values : Final(a, v)}
Resolved(a) == a \in deadRec \/ FinalValues(a) # {}

Validation(e) ==
    IF e \notin evid THEN "Unavailable"
    ELSE IF TruthOf(e) THEN "Valid" ELSE "Invalid"

\* =============================================================================
\* THE WALK (verifier)
\* =============================================================================

RejectedFinal(a) ==
    \E v \in FinalValues(a) :
        IF UnavailableAsInvalid THEN Validation(v) # "Valid"
        ELSE Validation(v) = "Invalid" /\ ~InvalidFinalNotSkipped

Skipped(a) == a \in deadRec \/ RejectedFinal(a)

AttemptLive(a) == AttemptLiveOmitted \/ \A b \in Attempts : b < a => Skipped(b)

\* E consumes the parent at attempt a through its trader's registered F there.
ConsumesAt(e, a) ==
    /\ \E f \in Fulfillments : EOf(f) = e /\ AttemptOf(f) = a /\ Registered(f)
    /\ Final(a, e)
    /\ Validation(e) = "Valid"
    /\ AttemptLive(a)

Consumers == {e \in Values : \E a \in Attempts : ConsumesAt(e, a)}

\* =============================================================================
\* ACTIONS
\* =============================================================================

\* Every step records what was ever final, ever registered, ever consumed.
Hist ==
    /\ everFinal' = [a \in Attempts |-> everFinal[a] \cup FinalValues(a)]
    /\ everReg' = [tr \in Traders |-> everReg[tr] \cup {f \in Options(tr) : Registered(f)}]
    /\ consHist' = consHist \cup Consumers

PredecessorResolved(a) == IF a = 0 THEN TRUE ELSE NumericHole \/ Resolved(a - 1)

\* A relayer delivers F to one member. Ingress: the precommit's key signed it,
\* the attempt's predecessor is resolved, and the member's K_ful(q) is empty.
Publish(f) ==
    /\ f \in Signed \/ RelayWithoutKeyBinding
    /\ PredecessorResolved(AttemptOf(f))
    /\ SumReg(TraderOf(f)) < Capacity
    /\ reg[f] < Finality
    /\ reg' = [reg EXCEPT ![f] = @ + 1]
    /\ Hist
    /\ UNCHANGED <<cell, deadRec, evid>>

\* A member admits E into key a for a registered F naming exactly that key.
WriteCell(a, v) ==
    /\ \/ CellsBeforeFulfillment
       \/ \E f \in Fulfillments :
             /\ EOf(f) = v
             /\ Registered(f)
             /\ AttemptOf(f) = a \/ FulfillmentSpray
    /\ PredecessorResolved(a)
    /\ SumCell(a) < Capacity
    /\ cell[a][v] < Finality
    /\ cell' = [cell EXCEPT ![a][v] = @ + 1]
    /\ Hist
    /\ UNCHANGED <<reg, deadRec, evid>>

\* A member that already holds v replaces it: the write-once rule removed.
Overwrite(a, v, w) ==
    /\ OverwriteAllowed
    /\ v # w
    /\ cell[a][v] > 0
    /\ cell' = [cell EXCEPT ![a][v] = @ - 1, ![a][w] = @ + 1]
    /\ Hist
    /\ UNCHANGED <<reg, deadRec, evid>>

\* A member loses a stored cell or K_ful entry: outside F0.
LoseCell(a, v) ==
    /\ PermanentStoreLoss
    /\ cell[a][v] > 0
    /\ cell' = [cell EXCEPT ![a][v] = @ - 1]
    /\ Hist
    /\ UNCHANGED <<reg, deadRec, evid>>

LoseReg(f) ==
    /\ PermanentStoreLoss
    /\ reg[f] > 0
    /\ reg' = [reg EXCEPT ![f] = @ - 1]
    /\ Hist
    /\ UNCHANGED <<cell, deadRec, evid>>

\* A verifier reads seenV holders of each value, seenEmpty empty members, and
\* leaves the rest unread (a timeout). ArithDead: max + #Empty + #Unknown < 3.
Max2(x, y) == IF x >= y THEN x ELSE y

DeadVerdict(seen1, seen2, seen3, seenEmpty) ==
    LET unread == N - seen1 - seen2 - seen3 - seenEmpty
        mx == Max2(seen1, Max2(seen2, seen3))
        open == IF UnreadDroppedFromCount THEN seenEmpty ELSE seenEmpty + unread
    IN  mx + open < Finality

RecordDead(a) ==
    /\ a \notin deadRec
    /\ \E seen1 \in 0..cell[a][E1], seen2 \in 0..cell[a][E2], seen3 \in 0..cell[a][E3],
          seenEmpty \in 0..(IF SumCell(a) <= N THEN N - SumCell(a) ELSE 0) :
          /\ seen1 + seen2 + seen3 + seenEmpty <= N
          /\ \/ DeadVerdict(seen1, seen2, seen3, seenEmpty)
             \/ TimeoutRecordsDead /\ seen1 + seen2 + seen3 + seenEmpty < N
    /\ deadRec' = deadRec \cup {a}
    /\ Hist
    /\ UNCHANGED <<reg, cell, evid>>

PublishEvidence(e) ==
    /\ e \notin evid
    /\ evid' = evid \cup {e}
    /\ Hist
    /\ UNCHANGED <<reg, cell, deadRec>>

Idle == UNCHANGED vars

Next ==
    \/ \E f \in Fulfillments : Publish(f)
    \/ \E a \in Attempts, v \in Values : WriteCell(a, v)
    \/ \E a \in Attempts, v \in Values, w \in Values : Overwrite(a, v, w)
    \/ \E a \in Attempts, v \in Values : LoseCell(a, v)
    \/ \E f \in Fulfillments : LoseReg(f)
    \/ \E a \in Attempts : RecordDead(a)
    \/ \E e \in Values : PublishEvidence(e)
    \/ Idle

Init ==
    /\ reg = [f \in Fulfillments |-> 0]
    /\ cell = [a \in Attempts |-> [v \in Values |-> 0]]
    /\ deadRec = {}
    /\ evid = {}
    /\ everFinal = [a \in Attempts |-> {}]
    /\ everReg = [tr \in Traders |-> {}]
    /\ consHist = {}

Spec == Init /\ [][Next]_vars

\* =============================================================================
\* INVARIANTS
\* =============================================================================

TypeOK ==
    /\ reg \in [Fulfillments -> 0..(N + 1)]
    /\ cell \in [Attempts -> [Values -> 0..(N + 1)]]
    /\ deadRec \subseteq Attempts
    /\ evid \subseteq Values

\* One final value per key, in this state and across all of history.
FinalUnique == \A a \in Attempts : Cardinality(everFinal[a] \cup FinalValues(a)) <= 1

\* A value once final stays final: no overwrite, no loss.
FinalityIsPermanent == \A a \in Attempts : everFinal[a] \subseteq FinalValues(a)

\* A Dead record never meets a final.
RecordsNeverContradict == \A a \in deadRec : everFinal[a] \cup FinalValues(a) = {}

\* Storage projection: no cell at attempt a + 1 before attempt a is resolved.
NoNumericHoles == \A a \in Attempts : a > 0 /\ SumCell(a) > 0 => Resolved(a - 1)

\* A cell holds E only for a registered F naming exactly that key.
CellsOnlyAfterFulfillmentRegistered ==
    \A a \in Attempts, v \in Values :
        cell[a][v] > 0 => \E f \in Fulfillments : EOf(f) = v /\ AttemptOf(f) = a /\ Registered(f)

\* A registered F was signed under its precommit's key.
RelayNeverForges == \A f \in Fulfillments : Registered(f) => f \in Signed

\* At most one F ever registers at a position, and registration is permanent.
OneFulfillmentPerPosition == \A tr \in Traders : Cardinality(everReg[tr]) <= 1
RegistrationIsPermanent == \A tr \in Traders : \A f \in everReg[tr] : Registered(f)

\* A position split between two of its own F registers neither, so it writes
\* nothing into the parent.
SelfSplitCreatesNoCells ==
    (\A f \in Options(U) : ~Registered(f)) => \A a \in Attempts : cell[a][E2] = 0

\* One consumer per parent, ever.
OneConsumerPerParent == Cardinality(consHist \cup Consumers) <= 1

\* A consumer at attempt a had every earlier attempt objectively skipped.
ObjectivelySkipped(b) ==
    \/ b \in deadRec
    \/ \E v \in FinalValues(b) : Validation(v) = "Invalid"

ConsumedImpliesAttemptLive ==
    \A e \in Values, a \in Attempts :
        ConsumesAt(e, a) => \A b \in Attempts : b < a => ObjectivelySkipped(b)

\* A final whose validation is known Invalid is skipped.
ObjectiveRejectionImpliesSkipped ==
    \A a \in Attempts : (\E v \in FinalValues(a) : Validation(v) = "Invalid") => Skipped(a)

\* Only a Dead record or a known-Invalid final makes a key skippable.
UnavailableNeverRejects == \A a \in Attempts : Skipped(a) => ObjectivelySkipped(a)

\* -----------------------------------------------------------------------------
\* NON-VACUITY, NEGATED. Each is listed only in a config that must violate it.
\* -----------------------------------------------------------------------------
NeverConsumed == Consumers = {}
NeverConsumedAtSecondAttempt == \A e \in Values : ~ConsumesAt(e, 1)
NeverDeadRecorded == deadRec = {}
NoSelfSplit ==
    ~(/\ \A f \in Options(U) : ~Registered(f)
      /\ \A f \in Options(U) : reg[f] >= 2)

====
