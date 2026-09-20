---- MODULE DSM_SofiSuccessorCells ----
EXTENDS Naturals, FiniteSets, TLC

\* =============================================================================
\* SOFI SUCCESSOR CELLS AND THE POSITION PAIR, AT THE MEMBERS: LEADER FIRST.
\*
\* SCOPE. One DLV parent's attempt keys K^(0), K^(1), and one trader position
\* q with its pair K_ful(q), K_root(q), replicated across the frozen
\* five-member set S (Part II of the specification: Sections 6 to 13). This
\* module owns what happens at the MEMBERS while writers, Core readers and
\* faults interleave. A member keeps what it is given, in arrival order, and
\* decides nothing: no ingress rule, no refusal, no comparison, no record.
\* Every fact below is derived by the WRITER or by CORE from raw reads.
\*
\* LEADER FIRST (Sections 7 and 8). The writer computes one leader per key from
\* a seed and the committed set S, writes there first, then copies. Core derives
\*   LeaderHeld(K, x) == x is the first object naming K in the leader's read
\*   Final(K, x)      == LeaderHeld(K, x) /\ two other members hold x
\* No member votes and nothing is counted against a quorum. No key is ever
\* dead: a key is open until an object naming it reaches its leader.
\*
\* THE MODEL
\*   members     the leader of a key is a fixed position of S, never a node's
\*               choice; the three members that are neither the leader nor
\*               the alternate are interchangeable copies, so they are held as
\*               a count per value, stopped at two (all Final needs)
\*   attempt keys K0, K1 of one parent; values: XT (the exercise of trader T's
\*               F, naming attempt AttemptT), XU (a rival's exercise, racing
\*               at K0), G (bytes that name the key but carry nothing Core can
\*               classify -- the pre-R11 shape that P1 of Section 42.3 is
\*               about, racing at K0)
\*   position q  of trader T: K_ful(q) may hold F (T's fulfillment);
\*               K_root(q) may hold C (the conditional claim F installs) or S
\*               (an ordinary claim at q, modelled as the race at the leader
\*               only). Both keys share one leader, and the pair is written
\*               there together.
\*   readers     Core reads any subset of the members; an unread member is
\*               Unknown and counts as nothing
\*   T           signs F, then anyone may write F, C and XT; the rival writes
\*               XU; anyone may write G. F names attempt AttemptT; the rival's
\*               own registration and evidence are taken as settled facts
\*
\* FALSIFICATIONS. Each DSM_SofiSuccessorCells_<Name>.cfg flips one constant
\* below (or states a claim that must be false) and lists exactly the invariant
\* it must violate; tools/vertical_validation/src/tla_runner.rs gates the
\* verdict and tla/README.md tabulates them.
\* =============================================================================

CONSTANTS
    N,                        \* members in the frozen set (5)
    MaxStep,                  \* DFID depth budget (runner reads it)
    ValidE1,                  \* [TRUE] RouteValidation of T's operation once evidence exists
    ValidE2,                  \* [TRUE] RouteValidation of the rival's operation
    ConformingF,              \* [TRUE] FulfillmentConformance(F)
    AttemptT,                 \* [0] the attempt F names at this parent
    RivalRegistered,          \* [TRUE] the rival's fulfillment is registered at its own position
    ExerciseCarriesClosure,   \* [FALSE] R11: only self-classifying exercises can occupy a successor key
    CountWithoutLeader,       \* [FALSE] finality counted over any three holders
    AvailabilityLeader,       \* [FALSE] the leader is whoever is reachable
    UnreadCountedAsCopy,      \* [FALSE] an unread member counts as a holder
    SplitPositionPair,        \* [FALSE] K_ful(q) and K_root(q) written in two steps
    OccupancyIsConsumption,   \* [FALSE] a final exercise consumes with no Core predicate
    RegistrationIsConformance,\* [FALSE] a registered F is taken as conforming
    ExerciseCountsAnywhere,   \* [FALSE] an exercise counts at a key it does not name
    AttemptLiveOmitted,       \* [FALSE] consumption without AttemptLive
    UnavailableAsInvalid,     \* [FALSE] missing evidence rejects a final
    InvalidFinalNotSkipped    \* [FALSE] an Invalid final is not skipped

ASSUME N = 5 /\ MaxStep \in Nat /\ AttemptT \in {0, 1}

NONE == "none"
FINALITY == 3
\* Copies are counted up to what Final needs. Counting WITHOUT the leader needs
\* a third holder of a value the leader never held first, so that mutation
\* lets one more copy land.
CopyCap == IF CountWithoutLeader THEN 3 ELSE 2

\* ---- keys and values ----------------------------------------------------
K0 == "K0"
K1 == "K1"
KF == "KF"
KR == "KR"
AttemptKeys == {K0, K1}
Keys == {K0, K1, KF, KR}
AttemptOf(k) == IF k = K0 THEN 0 ELSE 1

XT == "XT"
XU == "XU"
G == "G"
F == "F"
C == "C"
S == "S"
ValuesAt(k) ==
    CASE k = K0 -> {XT, XU, G}
      [] k = K1 -> {XT}
      [] k = KF -> {F}
      [] OTHER -> {C, S}
AllValues == {XT, XU, G, F, C, S}

\* The leader of a key is a position of S fixed by the seed. "L" is that
\* position; "A" is the alternate a reachability-based fallback would pick.
L == "L"
A == "A"
Slots == {L, A}

VARIABLES
    first,      \* [Keys -> [Slots -> value]]: the first object naming the key at that member
    copies,     \* [Keys -> [AllValues -> 0..2]]: the three copy members holding the value
    leaderUp,   \* the seeded leader is reachable (changes only under AvailabilityLeader)
    signedF,    \* T has signed F (nobody else can produce it)
    evid,       \* T's validation evidence is available
    everFinal,  \* [Keys -> values ever Final there]
    consHist    \* E values ever observed consuming the parent

vars == <<first, copies, leaderUp, signedF, evid, everFinal, consHist>>

\* ---- what Core derives from a read ----------------------------------------
\* The leader Core and the writer use. Never a node's decision: under the
\* standard configuration it is the seeded position L whatever is reachable.
Lead == IF AvailabilityLeader /\ ~leaderUp THEN A ELSE L

LeaderHeld(k, v) == first[k][Lead] = v

Holders(k, v) ==
    copies[k][v]
    + (IF first[k][L] = v THEN 1 ELSE 0)
    + (IF first[k][A] = v THEN 1 ELSE 0)

OthersHolding(k, v) == Holders(k, v) - 1

Final(k, v) ==
    IF CountWithoutLeader THEN Holders(k, v) >= FINALITY
    ELSE LeaderHeld(k, v) /\ OthersHolding(k, v) >= FINALITY - 1

FinalValues(k) == {v \in ValuesAt(k) : Final(k, v)}

\* A partial read: `unread` copy members answered nothing. Core evaluates the
\* rule over what it saw; an unread member counts as nothing.
ReadFinal(k, v, unreadCopies) ==
    LET answered == IF copies[k][v] > unreadCopies THEN copies[k][v] - unreadCopies ELSE 0
        seen == IF UnreadCountedAsCopy THEN answered + unreadCopies ELSE answered
        others == seen + (IF Lead = L /\ first[k][A] = v THEN 1 ELSE 0)
                       + (IF Lead = A /\ first[k][L] = v THEN 1 ELSE 0)
    IN LeaderHeld(k, v) /\ others >= FINALITY - 1

\* ---- the SoFi facts Core derives (Section 13) ------------------------------
FulfillmentRegistered == Final(KF, F) /\ Final(KR, C)
OrdinaryClaimRegistered == Final(KR, S)

\* T's evidence arrives late; the rival's is taken as present.
Validation(e) ==
    IF e = XT /\ ~evid THEN "Unavailable"
    ELSE IF (e = XT /\ ValidE1) \/ (e = XU /\ ValidE2) THEN "Valid" ELSE "Invalid"

Conformance ==
    IF RegistrationIsConformance /\ FulfillmentRegistered THEN "Valid"
    ELSE IF ConformingF THEN "Valid" ELSE "Invalid"

\* The exercise that counts at an attempt key: it names that attempt.
NamesKey(k, v) ==
    \/ v = XT /\ (AttemptT = AttemptOf(k) \/ ExerciseCountsAnywhere)
    \/ v = XU

\* Whether the value final at k can be classified at all. G names the key but
\* carries nothing Core can rebuild: not Invalid, not impossible, not consumed.
Impossible(v) ==
    \/ v = XT /\ (Validation(XT) = "Invalid" \/ Conformance = "Invalid")
    \/ v = XU /\ Validation(XU) = "Invalid"

RejectedFinal(k) ==
    \E v \in FinalValues(k) :
        /\ NamesKey(k, v)
        /\ IF UnavailableAsInvalid THEN ~(v = XT /\ Validation(XT) = "Valid" /\ Conformance = "Valid")
                                          /\ ~(v = XU /\ Validation(XU) = "Valid")
           ELSE Impossible(v) /\ ~InvalidFinalNotSkipped

Skipped(k) == RejectedFinal(k)

AttemptLive(k) == AttemptLiveOmitted \/ (k = K1 => Skipped(K0))

\* E consumes the parent at k: every Core predicate, never occupancy alone.
ConsumesAt(e, k) ==
    /\ Final(k, e)
    /\ NamesKey(k, e)
    /\ AttemptLive(k)
    /\ \/ OccupancyIsConsumption
       \/ e = XT /\ FulfillmentRegistered /\ Conformance = "Valid" /\ Validation(XT) = "Valid"
       \/ e = XU /\ RivalRegistered /\ Validation(XU) = "Valid"

Consumers == {e \in {XT, XU} : \E k \in AttemptKeys : ConsumesAt(e, k)}

\* ---- actions: members keep what they are given ---------------------------
Hist ==
    /\ everFinal' = [k \in Keys |-> everFinal[k] \cup FinalValues(k)]
    /\ consHist' = consHist \cup Consumers

\* A value may be produced at all: F, C and XT exist once T signed F; the
\* rival's exercise and an ordinary claim always exist; G exists until R11
\* makes every successor-key value an exercise that carries its closure.
Producible(k, v) ==
    CASE v \in {F, C, XT} -> signedF
      [] v = G -> ~ExerciseCarriesClosure
      [] OTHER -> TRUE

\* The writer's first write for k goes to the leader it computed. The member
\* keeps the value after anything already held: only the first is recorded,
\* because only the first decides anything.
PutLeader(k, v) ==
    /\ k \in AttemptKeys \/ (k = KR /\ v = S)
    /\ v \in ValuesAt(k)
    /\ Producible(k, v)
    /\ first[k][Lead] = NONE
    /\ first' = [first EXCEPT ![k][Lead] = v]
    /\ Hist
    /\ UNCHANGED <<copies, leaderUp, signedF, evid>>

\* A copy: any member other than the one that decides; any party carries the
\* bytes. The writer goes to the leader first (Section 8), so copies follow
\* the value that won there. A loser's copies exist too and count for nothing;
\* they are modelled only where counting them is the mutation.
PutCopy(k, v) ==
    /\ v \in ValuesAt(k)
    /\ v # S
    /\ Producible(k, v)
    /\ first[k][Lead] = v \/ (CountWithoutLeader /\ first[k][Lead] # NONE)
    /\ copies[k][v] < CopyCap
    /\ copies' = [copies EXCEPT ![k][v] = @ + 1]
    /\ Hist
    /\ UNCHANGED <<first, leaderUp, signedF, evid>>

\* The trader's position pair is written together at its one leader
\* (Section 9). The ordinary claim S races C there.
PutPair ==
    /\ signedF
    /\ ~SplitPositionPair
    /\ first[KF][Lead] = NONE
    /\ first' = [first EXCEPT ![KF][Lead] = F,
                              ![KR][Lead] = IF first[KR][Lead] = NONE THEN C ELSE @]
    /\ Hist
    /\ UNCHANGED <<copies, leaderUp, signedF, evid>>

PutHalf(k) ==
    /\ SplitPositionPair
    /\ signedF
    /\ k \in {KF, KR}
    /\ first[k][Lead] = NONE
    /\ first' = [first EXCEPT ![k][Lead] = IF k = KF THEN F ELSE C]
    /\ Hist
    /\ UNCHANGED <<copies, leaderUp, signedF, evid>>

SignF ==
    /\ ~signedF
    /\ signedF' = TRUE
    /\ Hist
    /\ UNCHANGED <<first, copies, leaderUp, evid>>

PublishEvidence ==
    /\ ~evid
    /\ evid' = TRUE
    /\ Hist
    /\ UNCHANGED <<first, copies, leaderUp, signedF>>

\* Under the availability mutation the seeded leader goes unreachable or
\* comes back. A member's reachability changes nothing a member holds.
Crash ==
    /\ AvailabilityLeader
    /\ leaderUp
    /\ leaderUp' = FALSE
    /\ Hist
    /\ UNCHANGED <<first, copies, signedF, evid>>

Recover ==
    /\ AvailabilityLeader
    /\ ~leaderUp
    /\ leaderUp' = TRUE
    /\ Hist
    /\ UNCHANGED <<first, copies, signedF, evid>>

Idle == UNCHANGED vars

Next ==
    \/ \E k \in Keys, v \in AllValues : PutLeader(k, v)
    \/ \E k \in Keys, v \in AllValues : PutCopy(k, v)
    \/ PutPair
    \/ \E k \in {KF, KR} : PutHalf(k)
    \/ SignF
    \/ PublishEvidence
    \/ Crash
    \/ Recover
    \/ Idle

Init ==
    /\ first = [k \in Keys |-> [s \in Slots |-> NONE]]
    /\ copies = [k \in Keys |-> [v \in AllValues |-> 0]]
    /\ leaderUp = TRUE
    /\ signedF = FALSE
    /\ evid = FALSE
    /\ everFinal = [k \in Keys |-> {}]
    /\ consHist = {}

Spec == Init /\ [][Next]_vars

\* =============================================================================
\* INVARIANTS
\* =============================================================================

TypeOK ==
    /\ first \in [Keys -> [Slots -> AllValues \cup {NONE}]]
    /\ copies \in [Keys -> [AllValues -> 0..3]]
    /\ evid \in BOOLEAN

\* FinalRequiresLeader: Final(K, x) implies LeaderHeld(K, x).
FinalRequiresLeader == \A k \in Keys : \A v \in ValuesAt(k) : Final(k, v) => LeaderHeld(k, v)

\* AtMostOneFinalPerCoordinate: one final value per key, now and ever.
AtMostOneFinalPerCoordinate ==
    \A k \in Keys : Cardinality(everFinal[k] \cup FinalValues(k)) <= 1

\* LeaderFromCommittedSet: the leader is a function of the seed and S only.
LeaderFromCommittedSet == Lead = L

\* Members never lose or replace: a final value stays final. (That the first
\* object at a leader never changes is the shape of `first`: a put lands there
\* only while it holds nothing.)
FinalityIsPermanent == \A k \in Keys : everFinal[k] \subseteq FinalValues(k)

\* A Core reader that saw a final on a partial read saw a real one.
PartialReadIsSound ==
    \A k \in Keys : \A v \in ValuesAt(k), u \in 0..3 : ReadFinal(k, v, u) => Final(k, v)

\* PositionPairAtomic: when K_ful(q) holds F first, K_root(q)'s race was settled
\* in the same write; no reachable state holds one half of an installed pair.
PositionPairAtomic == LeaderHeld(KF, F) => first[KR][Lead] # NONE

\* Mutual exclusion at q: a registered fulfillment means its own C_q is the
\* registered root.
PairMutualExclusion == FulfillmentRegistered => Final(KR, C) /\ ~LeaderHeld(KR, S)

\* Stored is not valid; registered is not valid.
EarlyCellCannotCauseConsumption ==
    \A k \in AttemptKeys : ConsumesAt(XT, k) => FulfillmentRegistered
\* Stated against the FACT (ConformingF), not the verifier's answer, so a
\* verifier that reads registration as conformance is caught.
RegistrationIsNotConformance ==
    FulfillmentRegistered /\ ~ConformingF => XT \notin Consumers
InvalidStoredNeverAdmitted ==
    \A k \in AttemptKeys : Final(k, XT) /\ Impossible(XT) => XT \notin Consumers
ExerciseNamesItsKey ==
    \A k \in AttemptKeys : ConsumesAt(XT, k) => AttemptT = AttemptOf(k)

\* One consumer per parent, ever; a consumer had every earlier attempt skipped.
OneConsumerPerParent == Cardinality(consHist \cup Consumers) <= 1
ConsumedImpliesAttemptLive ==
    \A e \in {XT, XU}, k \in AttemptKeys : ConsumesAt(e, k) => (k = K1 => Skipped(K0))

\* Only an objective rejection skips a key; Unavailable never does.
ObjectivelySkipped(k) == \E v \in FinalValues(k) : NamesKey(k, v) /\ Impossible(v)
ObjectiveRejectionImpliesSkipped == \A k \in AttemptKeys : ObjectivelySkipped(k) => Skipped(k)
UnavailableNeverRejects == \A k \in AttemptKeys : Skipped(k) => ObjectivelySkipped(k)

\* -----------------------------------------------------------------------------
\* P1 (Section 42.3): a value that names the key but carries nothing Core can
\* classify may win its leader and become final. The key is then occupied
\* forever and the next attempt never becomes live. Expected to FAIL until
\* rebuild step R11 makes every successor-key value an exercise that carries
\* its closure (ExerciseCarriesClosure).
\* -----------------------------------------------------------------------------
NoUnclassifiableOccupiedAttempt == \A k \in AttemptKeys : ~Final(k, G)

\* -----------------------------------------------------------------------------
\* NON-VACUITY, NEGATED. Each is listed only in a config that must violate it.
\* -----------------------------------------------------------------------------
NeverConsumed == Consumers = {}
NeverConsumedAtSecondAttempt == ~ConsumesAt(XT, K1)
NeverEarlyOccupied == ~(Final(K1, XT) /\ ~Skipped(K0))
NeverRegistered == ~FulfillmentRegistered
NeverLostAtLeader == ~(LeaderHeld(K0, XU) /\ FulfillmentRegistered /\ AttemptT = 0)

====
