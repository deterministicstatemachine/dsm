---- MODULE DSM_SofiSuccessorCells ----
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* =============================================================================
\* SOFI SUCCESSOR CELLS AND THE POSITION PAIR, AT THE MEMBERS: LEADER FIRST,
\* BEHIND THE RECOGNITION BOUNDARY.
\*
\* SCOPE. One DLV parent's attempt keys K^(0), K^(1), and one trader position
\* q with its pair K_ful(q), K_root(q), replicated across the frozen
\* five-member set S (Part II of the specification: Sections 6 to 13). This
\* module owns what happens at the MEMBERS while writers, hostile callers,
\* Core readers and faults interleave. A member keeps whatever bytes it is
\* given, in arrival order, and decides nothing: no ingress rule, no refusal,
\* no comparison, no record. Every fact below is derived by the WRITER or by
\* CORE from raw reads.
\*
\* TWO UNIVERSES. Raw member storage holds bytes from anyone. Between those
\* bytes and every protocol fact stands one deterministic function, Core's
\* recognition: it rebuilds a candidate from the bytes it reads and keeps it
\* only if what it recomputes is an object whose own fields name the key
\* (Section 8: "bytes that are not an object naming the key count as nothing
\* anywhere, because only objects exist"; Section 17.5). The winner at a key
\* is the FIRST RECOGNIZED OBJECT at the leader -- not the first bytes that
\* arrived. Unrecognized bytes are never an occupant, never final and never
\* consume, however early they arrived and however many members hold them.
\*
\*   raw bytes at a member  --recognition-->  protocol object  --> cell facts
\*
\* LEADER FIRST (Sections 7 and 8), over the recognized view:
\*   LeaderHeld(K, x) == x is the first recognized object naming K at the leader
\*   Final(K, x)      == LeaderHeld(K, x) /\ two other members hold x
\* No member votes and nothing is counted against a quorum. No key is ever
\* dead: a key is open until an object naming it reaches its leader.
\*
\* THE MODEL
\*   members     the leader of a key is a fixed position of S, never a node's
\*               choice; the three members that are neither the leader nor
\*               the alternate are interchangeable copies, so they are held as
\*               a count per value, stopped at two (all Final needs)
\*   attempt keys K0, K1 of one parent. Raw values: XT (the exercise of trader
\*               T's F, an object naming attempt AttemptT), XU (a rival's
\*               exercise, an object naming attempt 0), G (bytes any caller
\*               may send that no recognition can rebuild into an object).
\*               The leader keeps its raw arrival ORDER; copies are counts.
\*   position q  of trader T: K_ful(q) holds F (T's fulfillment); K_root(q)
\*               holds C (the conditional claim F installs) or S (an ordinary
\*               claim at q). Both keys share one leader, and the pair is
\*               written there together.
\*   readers     Core reads any subset of the members; an unread member is
\*               Unknown and counts as nothing
\*   T           signs F, then anyone may write F, C and XT; the rival writes
\*               XU; anyone writes G, anywhere, any time. F names attempt
\*               AttemptT; the rival's own registration and evidence are taken
\*               as settled facts
\*
\* FALSIFICATIONS. Each DSM_SofiSuccessorCells_<Name>.cfg flips one constant
\* below (or states a claim that must be false) and lists exactly the invariant
\* it must violate; tools/vertical_validation/src/tla_runner.rs gates the
\* verdict and tla/README.md tabulates them.
\* =============================================================================

CONSTANTS
    N,                        \* members in the frozen set (5)
    MaxStep,                  \* depth budget (the runner reads it; this model is finite)
    ValidE1,                  \* [TRUE] RouteValidation of T's operation once evidence exists
    ValidE2,                  \* [TRUE] RouteValidation of the rival's operation
    ConformingF,              \* [TRUE] FulfillmentConformance(F)
    AttemptT,                 \* [0] the attempt F names at this parent
    RivalRegistered,          \* [TRUE] the rival's fulfillment is registered at its own position
    RecognizeAnyBytes,        \* [FALSE] recognition promotes bytes it cannot rebuild into an object
    ExerciseCountsAnywhere,   \* [FALSE] recognition reads an exercise as naming a key it does not name
    CountWithoutLeader,       \* [FALSE] finality counted over any three holders
    AvailabilityLeader,       \* [FALSE] the leader is whoever is reachable
    UnreadCountedAsCopy,      \* [FALSE] an unread member counts as a holder
    SplitPositionPair,        \* [FALSE] K_ful(q) and K_root(q) written in two steps
    OccupancyIsConsumption,   \* [FALSE] a final value consumes with no Core predicate
    RegistrationIsConformance,\* [FALSE] a registered F is taken as conforming
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
RawAt(k) ==
    CASE k = K0 -> {XT, XU, G}
      [] k = K1 -> {XT, G}
      [] k = KF -> {F}
      [] OTHER -> {C, S}
AllValues == {XT, XU, G, F, C, S}

L == "L"
A == "A"
Slots == {L, A}

VARIABLES
    raw,        \* [AttemptKeys -> [Slots -> Seq(bytes)]]: what the leader and the alternate hold, in arrival order
    first,      \* [{KF, KR} -> [Slots -> value]]: the first object naming the position key at that member
    copies,     \* [Keys -> [AllValues -> 0..3]]: the three copy members holding the value
    leaderUp,   \* the seeded leader is reachable (changes only under AvailabilityLeader)
    signedF,    \* T has signed F (nobody else can produce F, C or XT)
    evid,       \* T's validation evidence is available
    everFinal,  \* [Keys -> values ever Final there]
    consHist    \* E values ever observed consuming the parent

vars == <<raw, first, copies, leaderUp, signedF, evid, everFinal, consHist>>

\* ---- the recognition boundary ------------------------------------------
\* THE FACT: b is a canonical object whose own fields name attempt key k
\* (Section 17.5: its F names (v, a) and its P names (v, R_n)). G names nothing:
\* no recomputation rebuilds it into an object.
TrueNamesKey(k, b) ==
    \/ b = XT /\ AttemptT = AttemptOf(k)
    \/ b = XU /\ k = K0

\* Core's recognition of the bytes b read at attempt key k: the object, or
\* nothing. The mutations promote bytes that name nothing, or an exercise
\* read at a key it does not name.
Recognized(k, b) ==
    \/ TrueNamesKey(k, b)
    \/ RecognizeAnyBytes /\ b = G
    \/ ExerciseCountsAnywhere /\ b = XT

\* An object Core can construct at all: XT exists only from T's signed F; the
\* rival's exercise from the rival's; G from nothing.
Constructible(b) ==
    \/ b = XT /\ signedF
    \/ b = XU

\* The first RECOGNIZED object at a member, over its raw arrival order.
RECURSIVE FirstRecognized(_, _)
FirstRecognized(k, seq) ==
    IF seq = <<>> THEN NONE
    ELSE IF Recognized(k, Head(seq)) THEN Head(seq)
    ELSE FirstRecognized(k, Tail(seq))

\* ---- what Core derives from a read ----------------------------------------
Lead == IF AvailabilityLeader /\ ~leaderUp THEN A ELSE L

Occupant(k, sl) == IF k \in AttemptKeys THEN FirstRecognized(k, raw[k][sl]) ELSE first[k][sl]

LeaderHeld(k, v) == Occupant(k, Lead) = v

Holders(k, v) ==
    copies[k][v]
    + (IF Occupant(k, L) = v THEN 1 ELSE 0)
    + (IF Occupant(k, A) = v THEN 1 ELSE 0)

OthersHolding(k, v) == Holders(k, v) - 1

Final(k, v) ==
    IF CountWithoutLeader THEN Holders(k, v) >= FINALITY
    ELSE LeaderHeld(k, v) /\ OthersHolding(k, v) >= FINALITY - 1

FinalValues(k) == {v \in RawAt(k) : Final(k, v)}

\* A partial read: `unread` copy members answered nothing. Core evaluates the
\* rule over what it saw; an unread member counts as nothing.
ReadFinal(k, v, unreadCopies) ==
    LET answered == IF copies[k][v] > unreadCopies THEN copies[k][v] - unreadCopies ELSE 0
        seen == IF UnreadCountedAsCopy THEN answered + unreadCopies ELSE answered
        others == seen + (IF Lead = L /\ Occupant(k, A) = v THEN 1 ELSE 0)
                       + (IF Lead = A /\ Occupant(k, L) = v THEN 1 ELSE 0)
    IN LeaderHeld(k, v) /\ others >= FINALITY - 1

\* ---- the SoFi facts Core derives (Section 13) ------------------------------
FulfillmentRegistered == Final(KF, F) /\ Final(KR, C)

Validation(e) ==
    IF e = XT /\ ~evid THEN "Unavailable"
    ELSE IF (e = XT /\ ValidE1) \/ (e = XU /\ ValidE2) THEN "Valid" ELSE "Invalid"

Conformance ==
    IF RegistrationIsConformance /\ FulfillmentRegistered THEN "Valid"
    ELSE IF ConformingF THEN "Valid" ELSE "Invalid"

Impossible(v) ==
    \/ v = XT /\ (Validation(XT) = "Invalid" \/ Conformance = "Invalid")
    \/ v = XU /\ Validation(XU) = "Invalid"

RejectedFinal(k) ==
    \E v \in FinalValues(k) :
        /\ Recognized(k, v)
        /\ IF UnavailableAsInvalid THEN ~(v = XT /\ Validation(XT) = "Valid" /\ Conformance = "Valid")
                                          /\ ~(v = XU /\ Validation(XU) = "Valid")
           ELSE Impossible(v) /\ ~InvalidFinalNotSkipped

Skipped(k) == RejectedFinal(k)

AttemptLive(k) == AttemptLiveOmitted \/ (k = K1 => Skipped(K0))

\* E consumes the parent at k: every Core predicate, never occupancy alone.
ConsumesAt(e, k) ==
    /\ Final(k, e)
    /\ Recognized(k, e)
    /\ AttemptLive(k)
    /\ \/ OccupancyIsConsumption
       \/ e = XT /\ FulfillmentRegistered /\ Conformance = "Valid" /\ Validation(XT) = "Valid"
       \/ e = XU /\ RivalRegistered /\ Validation(XU) = "Valid"

Consumers == {e \in AllValues : \E k \in AttemptKeys : ConsumesAt(e, k)}

\* ---- actions: members keep what they are given ---------------------------
Hist ==
    /\ everFinal' = [k \in Keys |-> everFinal[k] \cup FinalValues(k)]
    /\ consHist' = consHist \cup Consumers

\* Bytes may exist at all: F, C and XT once T signed F; the rival's exercise
\* and an ordinary claim always; G always -- anyone can send anything.
Producible(b) ==
    CASE b \in {F, C, XT} -> signedF
      [] OTHER -> TRUE

Holds(seq, b) == \E i \in 1..Len(seq) : seq[i] = b

\* Anyone sends any bytes to the leader of an attempt key. The member keeps
\* them after whatever it already holds. Nothing is checked: recognition
\* happens at READ time, in Core, never here.
PutRaw(k, b) ==
    /\ k \in AttemptKeys
    /\ b \in RawAt(k)
    /\ Producible(b)
    /\ ~Holds(raw[k][Lead], b)
    /\ raw' = [raw EXCEPT ![k][Lead] = Append(@, b)]
    /\ Hist
    /\ UNCHANGED <<first, copies, leaderUp, signedF, evid>>

\* A copy: any member other than the one that decides; any party carries any
\* bytes. Copies of the leader's occupant are what finality counts; a loser's
\* (or garbage's) copies are held too and count for nothing -- modelled where
\* counting them is the mutation.
PutCopy(k, b) ==
    /\ b \in RawAt(k)
    /\ b # S
    /\ Producible(b)
    /\ Occupant(k, Lead) = b \/ (CountWithoutLeader /\ Occupant(k, Lead) # NONE)
    /\ copies[k][b] < CopyCap
    /\ copies' = [copies EXCEPT ![k][b] = @ + 1]
    /\ Hist
    /\ UNCHANGED <<raw, first, leaderUp, signedF, evid>>

\* Garbage copies land anywhere, any time: a hostile caller spraying members.
PutGarbageCopy(k) ==
    /\ k \in AttemptKeys
    /\ copies[k][G] < CopyCap
    /\ copies' = [copies EXCEPT ![k][G] = @ + 1]
    /\ Hist
    /\ UNCHANGED <<raw, first, leaderUp, signedF, evid>>

\* The ordinary claim S races C at K_root(q)'s leader.
PutOrdinaryClaim ==
    /\ first[KR][Lead] = NONE
    /\ first' = [first EXCEPT ![KR][Lead] = S]
    /\ Hist
    /\ UNCHANGED <<raw, copies, leaderUp, signedF, evid>>

\* The trader's position pair is written together at its one leader (Section 9).
PutPair ==
    /\ signedF
    /\ ~SplitPositionPair
    /\ first[KF][Lead] = NONE
    /\ first' = [first EXCEPT ![KF][Lead] = F,
                              ![KR][Lead] = IF first[KR][Lead] = NONE THEN C ELSE @]
    /\ Hist
    /\ UNCHANGED <<raw, copies, leaderUp, signedF, evid>>

PutHalf(k) ==
    /\ SplitPositionPair
    /\ signedF
    /\ k \in {KF, KR}
    /\ first[k][Lead] = NONE
    /\ first' = [first EXCEPT ![k][Lead] = IF k = KF THEN F ELSE C]
    /\ Hist
    /\ UNCHANGED <<raw, copies, leaderUp, signedF, evid>>

SignF ==
    /\ ~signedF
    /\ signedF' = TRUE
    /\ Hist
    /\ UNCHANGED <<raw, first, copies, leaderUp, evid>>

PublishEvidence ==
    /\ ~evid
    /\ evid' = TRUE
    /\ Hist
    /\ UNCHANGED <<raw, first, copies, leaderUp, signedF>>

Crash ==
    /\ AvailabilityLeader
    /\ leaderUp
    /\ leaderUp' = FALSE
    /\ Hist
    /\ UNCHANGED <<raw, first, copies, signedF, evid>>

Recover ==
    /\ AvailabilityLeader
    /\ ~leaderUp
    /\ leaderUp' = TRUE
    /\ Hist
    /\ UNCHANGED <<raw, first, copies, signedF, evid>>

Idle == UNCHANGED vars

Next ==
    \/ \E k \in AttemptKeys, b \in AllValues : PutRaw(k, b)
    \/ \E k \in Keys, b \in AllValues : PutCopy(k, b)
    \/ \E k \in AttemptKeys : PutGarbageCopy(k)
    \/ PutOrdinaryClaim
    \/ PutPair
    \/ \E k \in {KF, KR} : PutHalf(k)
    \/ SignF
    \/ PublishEvidence
    \/ Crash
    \/ Recover
    \/ Idle

Init ==
    /\ raw = [k \in AttemptKeys |-> [s \in Slots |-> <<>>]]
    /\ first = [k \in {KF, KR} |-> [s \in Slots |-> NONE]]
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
    /\ \A k \in AttemptKeys, s \in Slots : Len(raw[k][s]) <= 3
    /\ first \in [{KF, KR} -> [Slots -> AllValues \cup {NONE}]]
    /\ copies \in [Keys -> [AllValues -> 0..3]]
    /\ evid \in BOOLEAN

\* ---- the recognition boundary (P1 of Section 42.3, as invariants) ----------
\* Whatever bytes arrived, and in whatever order, an occupant is a recognized
\* object naming its key; nothing else is ever final or ever consumes.
UnrecognizedBytesNeverOccupy ==
    \A k \in AttemptKeys, sl \in Slots :
        Occupant(k, sl) # NONE => TrueNamesKey(k, Occupant(k, sl))
UnrecognizedBytesNeverFinalize == \A k \in AttemptKeys : ~Final(k, G)
UnrecognizedBytesNeverConsume == G \notin Consumers /\ G \notin consHist
RecognizedAttemptNamesItsKey ==
    \A k \in AttemptKeys, sl \in Slots :
        Occupant(k, sl) \in {XT, XU} => TrueNamesKey(k, Occupant(k, sl))
FinalImpliesRecognized ==
    \A k \in AttemptKeys : \A v \in FinalValues(k) : Recognized(k, v) /\ TrueNamesKey(k, v)
\* If Core recognizes it, Core could have constructed it (Read this first).
RecognizedImpliesConstructible ==
    \A k \in AttemptKeys, sl \in Slots :
        Occupant(k, sl) # NONE => Constructible(Occupant(k, sl))

\* ---- leader-first finality -------------------------------------------------
FinalRequiresLeader == \A k \in Keys : \A v \in RawAt(k) : Final(k, v) => LeaderHeld(k, v)
AtMostOneFinalPerCoordinate ==
    \A k \in Keys : Cardinality(everFinal[k] \cup FinalValues(k)) <= 1
LeaderFromCommittedSet == Lead = L
FinalityIsPermanent == \A k \in Keys : everFinal[k] \subseteq FinalValues(k)
PartialReadIsSound ==
    \A k \in Keys : \A v \in RawAt(k), u \in 0..3 : ReadFinal(k, v, u) => Final(k, v)

\* ---- the position pair -----------------------------------------------------
PositionPairAtomic == LeaderHeld(KF, F) => first[KR][Lead] # NONE
PairMutualExclusion == FulfillmentRegistered => Final(KR, C) /\ ~LeaderHeld(KR, S)

\* ---- stored is not valid; registered is not valid --------------------------
EarlyCellCannotCauseConsumption ==
    \A k \in AttemptKeys : ConsumesAt(XT, k) => FulfillmentRegistered
RegistrationIsNotConformance ==
    FulfillmentRegistered /\ ~ConformingF => XT \notin Consumers
InvalidStoredNeverAdmitted ==
    \A k \in AttemptKeys : Final(k, XT) /\ Impossible(XT) => XT \notin Consumers
ExerciseNamesItsKey ==
    \A k \in AttemptKeys : ConsumesAt(XT, k) => AttemptT = AttemptOf(k)

\* ---- the walk ---------------------------------------------------------------
OneConsumerPerParent == Cardinality(consHist \cup Consumers) <= 1
ConsumedImpliesAttemptLive ==
    \A e \in {XT, XU}, k \in AttemptKeys : ConsumesAt(e, k) => (k = K1 => Skipped(K0))
ObjectivelySkipped(k) == \E v \in FinalValues(k) : Recognized(k, v) /\ Impossible(v)
ObjectiveRejectionImpliesSkipped == \A k \in AttemptKeys : ObjectivelySkipped(k) => Skipped(k)
UnavailableNeverRejects == \A k \in AttemptKeys : Skipped(k) => ObjectivelySkipped(k)

\* -----------------------------------------------------------------------------
\* NON-VACUITY, NEGATED. Each is listed only in a config that must violate it.
\* -----------------------------------------------------------------------------
NeverConsumed == Consumers = {}
NeverConsumedAtSecondAttempt == ~ConsumesAt(XT, K1)
NeverEarlyOccupied == ~(Final(K1, XT) /\ ~Skipped(K0))
NeverRegistered == ~FulfillmentRegistered
NeverLostAtLeader == ~(LeaderHeld(K0, XU) /\ FulfillmentRegistered /\ AttemptT = 0)
\* Garbage physically arrives FIRST at the leader, garbage is held by every
\* copy member, and the exercise behind it is still the occupant -- final.
GarbageNeverArrivesFirst ==
    ~(/\ Len(raw[K0][L]) >= 1 /\ raw[K0][L][1] = G
      /\ copies[K0][G] = 2
      /\ Final(K0, XT))

====
