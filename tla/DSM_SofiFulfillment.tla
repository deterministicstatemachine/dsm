---- MODULE DSM_SofiFulfillment ----
EXTENDS Naturals, FiniteSets, TLC

\* =============================================================================
\* SOFI: ONE UNILATERAL TRADER OPERATION, RUN CONCURRENTLY.
\*
\* SCOPE. A route is one trader operation P -> G_1..G_n -> F -> realization
\* (Parts III and IV of the specification). This module owns the BEHAVIOUR of
\* that operation while it interleaves with everything else that can touch its
\* DLV parents: a rival trader consuming a parent between the witnesses and F,
\* the trader abandoning P or doing something else at its position, relayers
\* carrying exercises into successor keys, validation evidence arriving late,
\* a parent being orphaned, and a descendant claim at q + 1.
\*
\* Storage is at the level of the facts Core derives from raw reads
\* (Section 13): a successor key is empty or Final(x) for the x that won its leader; a
\* trader position holds one registered claim (Final at K_ful(q) and
\* K_root(q), which DSM_SofiSuccessorCells proves is one value per key). No
\* member records anything, no key is ever dead, and NOTHING STORES AN OUTCOME:
\* completion and permanent defeat are derived here from the leg reads
\* (Section 21). Stored is not valid and registered is not conforming: a
\* fulfillment registers with whatever bytes it carries, and Core's two
\* predicates -- RouteValidation, which contains SetupValid, and
\* FulfillmentConformance -- decide what it is worth.
\*
\* THE MODEL
\*   Parents   RA (vault A: keys at attempts 0 and 1), RB (vault B: attempt 0);
\*             whether each is canonical is settled once, by its own lineage
\*   P1        trader T, route over RA and RB, external commitment E1
\*   P2        trader U, single leg on RA, external commitment E2
\*   F         a precommit plus its attempt at RA, fixed at exercise time; it
\*             names the legs its witness set covers (possibly not all of P's)
\*   T may instead make an ordinary transition "S" at its position, and may
\*   claim position q + 1 ("C2" conditional, "S2" ordinary).
\*   T0        the claim at p that P1 names as its trader parent: either an
\*             ordinary single-root claim, or a conditional SoFi claim whose
\*             branch selection is decided later, by p's own resolution
\*
\* LIVENESS AS QUIESCENCE. Every action here is bounded, so every behaviour is
\* finite. Under weak fairness on the required (honest-completer) actions, a
\* behaviour ends only in a state where none of them is enabled. "A registered
\* F resolves" is therefore the INVARIANT Quiescent => Resolved, checked over
\* every reachable state. Trader actions are discretionary and never required.
\*
\* FALSIFICATIONS. Each DSM_SofiFulfillment_<Name>.cfg flips one constant below
\* (or states a claim that must be false) and lists exactly the invariant it
\* must violate; tools/vertical_validation/src/tla_runner.rs gates the verdict
\* and tla/README.md tabulates them.
\* =============================================================================

CONSTANTS
    ValidP1,                           \* [TRUE] the leg predicates of RouteValidation(P1)
    ValidP2,                           \* [TRUE] RouteValidation(P2) once evidence exists
    SetupValidP1,                      \* [TRUE] SetupValid of P1's legs' setups
    CreationValidB,                    \* [TRUE] vault B's creation validated
    MaxStep,                           \* DFID depth budget (runner reads it)
    EvidenceMayBeWithheld,             \* [FALSE] R13-5 assumption removed
    ProducerFailsClosed,               \* [TRUE] a producer signs F at attempt a > 0 only once K^(a-1) is permanently resolved (R6)
    SetupValidRemoved,                 \* [FALSE] RouteValidation without SetupValid
    ConformanceDropped,                \* [FALSE] ConsumedRoute without FulfillmentConformance
    RegistrationIsConformance,         \* [FALSE] a registered F is taken as conforming
    OccupancyIsConsumption,            \* [FALSE] final legs consume with no Core predicate
    PrecommitAsExercise,               \* [FALSE] storing P occupies the position
    LockingPolicyFulfillments,         \* [FALSE] a foreign witness refuses F
    CompleteWithoutCanonicalParents,   \* [FALSE] consumption ignores orphaned parents
    CompleteRejectedNotSkipped,        \* [FALSE] arm (i) gated on every leg being final
    OrphanNotSkipped,                  \* [FALSE] arm (ii) gated on every leg being final
    StaleLegNotSkipped,                \* [FALSE] arm (iii) gated on every leg being final
    VoidBeforeValidation,              \* [FALSE] Void without RouteValidation = Valid
    ParentBranchIgnored,               \* [FALSE] which branch T0 selected is not checked
    PendingParentIsImpossible,         \* [FALSE] an undecided T0 is treated as terminal
    OrdinaryClaimBypassesFence,        \* [FALSE] fence applied to conditional claims only
    DescendantOnStorageResolution,     \* [FALSE] q + 1 built once q is storage-resolved, not Core-resolved
    RegisteredGenesisAccepted,         \* [FALSE] the walk starts from a stored genesis
    TraderOnlyCompletion               \* [FALSE] a write authorization: only the trader completes

ASSUME MaxStep \in Nat

NONE == "none"
RA == "RA"
RB == "RB"
Parents == {RA, RB}
P1 == "P1"
P2 == "P2"
Precommits == {P1, P2}
T == "T"
U == "U"
Traders == {T, U}
E1 == "E1"
E2 == "E2"
Commitments == {E1, E2}

Trader(p) == IF p = P1 THEN T ELSE U
EOf(p) == IF p = P1 THEN E1 ELSE E2
LegsOf(p) == IF p = P1 THEN {RA, RB} ELSE {RA}
Truth(p) == IF p = P1 THEN ValidP1 ELSE ValidP2
SetupValid(p) == IF p = P1 THEN SetupValidP1 ELSE TRUE

Fulfillments == {<<P1, 0>>, <<P1, 1>>, <<P2, 0>>, <<P2, 1>>}
PrecommitOf(f) == f[1]
AttemptAt(f, r) == IF r = RA THEN f[2] ELSE 0
KeyOf(f, r) == <<r, AttemptAt(f, r)>>
Keys == {<<RA, 0>>, <<RA, 1>>, <<RB, 0>>}

\* A successor key as Core reads it: empty, or x is final. (That the leader's
\* first object settles the race before the copies land is the cells module's
\* fact; here a key resolves in one step, to the value that won its leader.)
KeyStates == {"empty"} \cup Commitments

ParentStates == {"single", "open", "taken", "other", "none"}

SlotNone == <<"none", 0>>
SlotS == <<"S", 0>>
SlotPrecommit == <<"precommit", 0>>

VARIABLES
    pStored,   \* content-addressed precommits: no position; once P is stored its
               \* trader may sign F at any time, so an exercise carrying F can exist
    gStored,   \* content-addressed witnesses <<precommit, parent>>
    slot,      \* [Traders -> registered claim at q]: SlotNone, SlotS, or an F
    covers,    \* [Traders -> the legs the registered F names]
    key,       \* [Keys -> KeyStates] what Core derives at each successor key
    evid,      \* precommits whose validation evidence is available
    canon,     \* [Parents -> unknown | canonical | orphan], from the parent's own lineage
    online,    \* traders able to act (matters only under TraderOnlyCompletion)
    claim2,    \* T's claim at q + 1
    parent,    \* the claim at p that P1 names: ParentStates
    resHist    \* [Traders -> first non-Pending resolution observed]

vars == <<pStored, gStored, slot, covers, key, evid, canon, online, claim2,
          parent, resHist>>

\* =============================================================================
\* THE VERIFIER: the two predicates, the walk, consumption, resolution
\* =============================================================================

\* RouteValidation (Section 20.1): SetupValid sits inside it.
Validation(p) ==
    IF p \notin evid THEN "Unavailable"
    ELSE IF Truth(p) /\ (SetupValidRemoved \/ SetupValid(p)) THEN "Valid" ELSE "Invalid"

Registered(tr) == slot[tr] \in Fulfillments
RegPrecommit(tr) == PrecommitOf(slot[tr])
FKeys(tr) == {KeyOf(slot[tr], r) : r \in covers[tr]}

\* A key's storage resolution is permanent once something is final there
\* (Section 23.1); another commitment final at a reserved key is a loss.
FinalE(k, e) == key[k] = e
LostTo(k, e) == key[k] \in Commitments \ {e}
PermanentlyResolved(k, e) == FinalE(k, e) \/ LostTo(k, e)

\* FulfillmentConformance (Section 20.2), for the registered F of tr:
\* item 3 (complete canonical witness set), item 5 (an earlier attempt has a
\* permanent storage resolution), evidence availability. Registration supplies
\* no truth value.
\* The structural fact, as the spec states it.
TrueConformance(tr) ==
    IF ~Registered(tr) THEN "Unavailable"
    ELSE LET p == RegPrecommit(tr) IN
         IF covers[tr] # LegsOf(p) THEN "Invalid"
         ELSE IF \E r \in covers[tr] : <<p, r>> \notin gStored THEN "Unavailable"
         ELSE IF AttemptAt(slot[tr], RA) = 1 /\ ~PermanentlyResolved(<<RA, 0>>, EOf(p))
              THEN "Unavailable"
         ELSE "Valid"

\* What the verifier answers; the mutation reads registration as conformance.
Conformance(tr) ==
    IF RegistrationIsConformance /\ Registered(tr) THEN "Valid" ELSE TrueConformance(tr)

\* THE TRADER PARENT (P15-3, R17-3).
ParentPending == parent = "open"
ParentImpossible ==
    \/ parent \in {"other", "none"}
    \/ PendingParentIsImpossible /\ ParentPending
ParentCompatible == ParentBranchIgnored \/ parent \in {"single", "taken"}

\* The walk starts only from an accepted genesis (F10).
WalkStart(r) == r = RA \/ CreationValidB \/ RegisteredGenesisAccepted

\* Whose exercise can be written at key k: a trader whose F (which exists
\* once its P does) names it. Registration is not required to write (early
\* occupancy is reachable); it is required to consume.
NamesKey(tr, k) ==
    /\ (IF tr = T THEN P1 ELSE P2) \in pStored
    /\ \E f \in Fulfillments : PrecommitOf(f) = (IF tr = T THEN P1 ELSE P2)
                               /\ k[1] \in LegsOf(PrecommitOf(f))
                               /\ KeyOf(f, k[1]) = k
                               /\ (Registered(tr) => f = slot[tr])

\* No precommit other than P1 names RB, so RB is never consumed by another E.
ConsumedByOtherRB == \E k \in Keys : k[1] = RB /\ LostTo(k, E1)

\* Every leg of P1 is final on E1 -- derived, never stored.
AllLegsFinalE1 == \A r \in LegsOf(P1) : Registered(T) /\ FinalE(KeyOf(slot[T], r), E1)

\* The route arms for an E1 cell at parent r (Section 23.5).
ArmI == Validation(P1) = "Invalid" \/ Conformance(T) = "Invalid"
ArmII(r) == \E r2 \in LegsOf(P1) \ {r} : canon[r2] = "orphan"
ArmIV == ~ParentBranchIgnored /\ ParentImpossible

RouteRejectedAtRA0 ==
    \/ ArmI /\ (CompleteRejectedNotSkipped => AllLegsFinalE1)
    \/ ArmII(RA) /\ (OrphanNotSkipped => AllLegsFinalE1)
    \/ ConsumedByOtherRB /\ (StaleLegNotSkipped => AllLegsFinalE1)
    \/ ArmIV

\* Arm (v), Section 21.1: the exercise final at k carries an F that can never
\* register, because position q already holds a different claim -- another F
\* of the same trader (naming another attempt) or an ordinary transition. Its
\* route is impossible at k. This arm reads no evidence.
LostPosition(k, tr) ==
    \/ slot[tr] = SlotS
    \/ Registered(tr) /\ k \notin FKeys(tr)

\* The attempt-0 key at RA, which every later attempt at RA depends on. A key
\* is skipped only on a FINAL value of an impossible operation; a held value
\* and an empty key are open.
Skipped0 ==
    \/ key[<<RA, 0>>] = E2 /\ (Validation(P2) = "Invalid" \/ LostPosition(<<RA, 0>>, U))
    \/ key[<<RA, 0>>] = E1 /\ (RouteRejectedAtRA0 \/ LostPosition(<<RA, 0>>, T))

LiveAt(r, a) == r = RB \/ a = 0 \/ Skipped0

ConsumedSingle ==
    /\ Registered(U)
    /\ Validation(P2) = "Valid"
    /\ (ConformanceDropped \/ Conformance(U) = "Valid")
    /\ canon[RA] = "canonical"
    /\ LiveAt(RA, AttemptAt(slot[U], RA))
    /\ FinalE(KeyOf(slot[U], RA), E2)

ArmIII(r) == IF r = RB THEN ConsumedSingle ELSE ConsumedByOtherRB

RouteImpossibleAt(r) ==
    \/ ArmI /\ (CompleteRejectedNotSkipped => AllLegsFinalE1)
    \/ ArmII(r) /\ (OrphanNotSkipped => AllLegsFinalE1)
    \/ ArmIII(r) /\ (StaleLegNotSkipped => AllLegsFinalE1)
    \/ ArmIV

Skipped(k) ==
    IF k = <<RA, 0>> THEN Skipped0
    ELSE \/ key[k] = E2 /\ (Validation(P2) = "Invalid" \/ LostPosition(k, U))
         \/ key[k] = E1 /\ (RouteImpossibleAt(k[1]) \/ LostPosition(k, T))

\* ConsumedRoute (Section 23.2): every Core predicate over every leg of P.
\* Under OccupancyIsConsumption, finality alone is taken as consumption.
ConsumedRoute ==
    IF OccupancyIsConsumption THEN AllLegsFinalE1
    ELSE
    /\ Registered(T)
    /\ RegPrecommit(T) = P1
    /\ (ConformanceDropped \/ Conformance(T) = "Valid")
    /\ Validation(P1) = "Valid"
    /\ ParentCompatible
    /\ \A r \in LegsOf(P1) :
          /\ CompleteWithoutCanonicalParents \/ canon[r] = "canonical"
          /\ WalkStart(r)
          /\ LiveAt(r, AttemptAt(slot[T], r))
          /\ FinalE(KeyOf(slot[T], r), E1)

ConsumersOf(r) ==
    (IF ConsumedRoute /\ r \in LegsOf(P1) THEN {E1} ELSE {})
    \cup (IF r = RA /\ ConsumedSingle THEN {E2} ELSE {})

Realized(tr) == IF tr = T THEN ConsumedRoute ELSE ConsumedSingle

\* StorageResolved: an input internal to resolution (Section 22), never a
\* predecessor authority.
StorageResolvedF(tr) ==
    \A k \in FKeys(tr) : PermanentlyResolved(k, EOf(RegPrecommit(tr)))

VoidEvidence(tr) ==
    LET e == EOf(RegPrecommit(tr)) IN
    \/ \E k \in FKeys(tr) : LostTo(k, e)
    \/ \E r \in covers[tr] : canon[r] = "orphan" \/ ConsumersOf(r) \ {e} # {}

\* The resolution ladder (Section 24). Rungs 1 and 2 are the trader parent;
\* rungs 3 and 4 are FulfillmentConformance; 5 and 6 RouteValidation; then
\* Realized, Void, Pending.
Resolve(tr) ==
    IF ~Registered(tr) THEN "Pending"
    ELSE IF tr = T /\ ~ParentBranchIgnored /\ ~PendingParentIsImpossible
            /\ ParentPending
         THEN "Pending"
    ELSE IF tr = T /\ ~ParentBranchIgnored /\ ParentImpossible THEN "Invalid"
    ELSE IF ~ConformanceDropped /\ Conformance(tr) = "Invalid" THEN "Invalid"
    ELSE IF ~ConformanceDropped /\ Conformance(tr) = "Unavailable" THEN "Pending"
    ELSE IF Validation(RegPrecommit(tr)) = "Invalid" THEN "Invalid"
    ELSE IF Validation(RegPrecommit(tr)) = "Unavailable" /\ ~VoidBeforeValidation THEN "Pending"
    ELSE IF Realized(tr) THEN "Realized"
    ELSE IF /\ (VoidBeforeValidation \/ Validation(RegPrecommit(tr)) = "Valid")
            /\ StorageResolvedF(tr)
            /\ VoidEvidence(tr)
         THEN "Void"
    ELSE "Pending"

\* Core-resolved: what a producer at q + 1 needs (Section 22).
CoreResolvedT ==
    \/ slot[T] = SlotS
    \/ Registered(T) /\ Resolve(T) # "Pending"

StorageResolvedT ==
    \/ slot[T] = SlotS
    \/ Registered(T) /\ StorageResolvedF(T)

\* =============================================================================
\* ACTIONS
\* =============================================================================

Hist == resHist' = [tr \in Traders |->
                      IF resHist[tr] = "Pending" THEN Resolve(tr) ELSE resHist[tr]]

CompleterOK(tr) == ~TraderOnlyCompletion \/ tr \in online

\* The trader publishes P. It occupies no position (unless mutated).
StoreP(p) ==
    /\ p \notin pStored
    /\ pStored' = pStored \cup {p}
    /\ slot' = IF PrecommitAsExercise /\ slot[Trader(p)] = SlotNone
                 THEN [slot EXCEPT ![Trader(p)] = SlotPrecommit]
                 ELSE slot
    /\ Hist
    /\ UNCHANGED <<gStored, covers, key, evid, canon, online, claim2, parent>>

\* Anyone computes and publishes a witness for a leg of a stored P.
StoreG(p, r) ==
    /\ p \in pStored
    /\ r \in LegsOf(p)
    /\ <<p, r>> \notin gStored
    /\ gStored' = gStored \cup {<<p, r>>}
    /\ Hist
    /\ UNCHANGED <<pStored, slot, covers, key, evid, canon, online, claim2, parent>>

\* F reaches the leader of its position pair first and registers with the
\* legs it names -- all of P's, or a subset (a malformed F: the store keeps it,
\* Core's conformance judges it). No member checks a witness, a predecessor
\* or a parent (R10-2). The only gate is the race at the leader.
\* The producer's own rule (R6, fail closed): it signs an F naming attempt 1
\* only once attempt 0 has a permanent storage resolution -- what
\* FulfillmentConformance item 5 will ask. A member never checks this; a
\* speculative producer that skips it strands its own position.
RegisterGuard(f) ==
    LET p == PrecommitOf(f) IN
    /\ p \in pStored
    /\ slot[Trader(p)] = SlotNone
    /\ ProducerFailsClosed /\ AttemptAt(f, RA) = 1 => PermanentlyResolved(<<RA, 0>>, EOf(p))
    /\ LockingPolicyFulfillments =>
          ~\E g \in gStored : g[1] # p /\ g[2] \in LegsOf(p) /\ ~Registered(Trader(g[1]))

Register(f, legs) ==
    LET p == PrecommitOf(f) IN
    /\ RegisterGuard(f)
    /\ legs \subseteq LegsOf(p) /\ legs # {}
    /\ slot' = [slot EXCEPT ![Trader(p)] = f]
    /\ covers' = [covers EXCEPT ![Trader(p)] = legs]
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, key, evid, canon, online, claim2, parent>>

\* An ordinary trader transition at q.
Transition ==
    /\ slot[T] = SlotNone
    /\ slot' = [slot EXCEPT ![T] = SlotS]
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, covers, key, evid, canon, online, claim2, parent>>

\* A relayer carries tr's exercise to a key it names; it wins the race at the
\* leader and the copies follow. Registration is not required to write --
\* only to consume.
WriteKey(k, tr) ==
    /\ key[k] = "empty"
    /\ NamesKey(tr, k)
    /\ CompleterOK(tr)
    /\ key' = [key EXCEPT ![k] = IF tr = T THEN E1 ELSE E2]
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, evid, canon, online, claim2, parent>>

PublishEvidence(p) ==
    /\ p \in pStored
    /\ p \notin evid
    /\ evid' = evid \cup {p}
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, key, canon, online, claim2, parent>>

\* The parent's own lineage settles whether it is canonical. Exogenous, once.
SettleParent(r, c) ==
    /\ canon[r] = "unknown"
    /\ canon' = [canon EXCEPT ![r] = c]
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, key, evid, online, claim2, parent>>

SelectParentBranch(b) ==
    /\ parent = "open"
    /\ parent' = b
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, key, evid, canon, online, claim2>>

GoOffline(tr) ==
    /\ TraderOnlyCompletion
    /\ tr \in online
    /\ online' = online \ {tr}
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, key, evid, canon, claim2, parent>>

\* A producer builds a claim at q + 1 only on a Core-resolved q, whatever the
\* claim's kind. The mutations build on storage resolution, or exempt
\* ordinary claims from the fence.
ClaimNext(kind) ==
    /\ claim2 = NONE
    /\ slot[T] # SlotNone
    /\ \/ (IF DescendantOnStorageResolution THEN StorageResolvedT ELSE CoreResolvedT)
       \/ (OrdinaryClaimBypassesFence /\ kind = "S2")
    /\ claim2' = kind
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, key, evid, canon, online, parent>>

Idle == UNCHANGED vars

Next ==
    \/ \E p \in Precommits : StoreP(p)
    \/ \E p \in Precommits, r \in Parents : StoreG(p, r)
    \/ \E f \in Fulfillments : \E legs \in {LegsOf(PrecommitOf(f)), {RA}} : Register(f, legs)
    \/ Transition
    \/ \E k \in Keys, tr \in Traders : WriteKey(k, tr)
    \/ \E p \in Precommits : PublishEvidence(p)
    \/ \E r \in Parents, c \in {"canonical", "orphan"} : SettleParent(r, c)
    \/ \E b \in {"taken", "other", "none"} : SelectParentBranch(b)
    \/ \E tr \in Traders : GoOffline(tr)
    \/ \E kind \in {"C2", "S2"} : ClaimNext(kind)
    \/ Idle

Init ==
    /\ pStored = {}
    /\ gStored = {}
    /\ slot = [tr \in Traders |-> SlotNone]
    /\ covers = [tr \in Traders |-> {}]
    /\ key = [k \in Keys |-> "empty"]
    /\ evid = {}
    /\ canon = [r \in Parents |-> "unknown"]
    /\ online = Traders
    /\ claim2 = NONE
    /\ parent \in {"single", "open"}
    /\ resHist = [tr \in Traders |-> "Pending"]

Spec == Init /\ [][Next]_vars

\* =============================================================================
\* QUIESCENCE: the required (honest-completer) actions
\* =============================================================================

ProgressEnabled ==
    \/ \E r \in Parents : canon[r] = "unknown"
    \/ ParentPending
    \* a registered F's keys still to write
    \/ \E k \in Keys, tr \in Traders :
          CompleterOK(tr) /\ Registered(tr) /\ k \in FKeys(tr) /\ key[k] = "empty"
    \/ ~EvidenceMayBeWithheld /\ \E p \in pStored : p \notin evid
    \/ \E tr \in Traders : Registered(tr) /\ \E r \in covers[tr] : <<RegPrecommit(tr), r>> \notin gStored
    \* an exercise of a trader who has not yet taken its position: that
    \* trader may still register the F it carries, so the key it occupies is
    \* a question only the trader can close (Section 25)
    \/ \E k \in Keys, tr \in Traders :
          key[k] = (IF tr = T THEN E1 ELSE E2) /\ slot[tr] = SlotNone

\* A rival that wants RA: its own flow is required too.
RivalProgressEnabled ==
    \/ P2 \notin pStored
    \/ <<P2, RA>> \notin gStored
    \/ \E f \in {<<P2, 0>>, <<P2, 1>>} : RegisterGuard(f)

\* =============================================================================
\* INVARIANTS
\* =============================================================================

TypeOK ==
    /\ pStored \subseteq Precommits
    /\ gStored \subseteq Precommits \X Parents
    /\ key \in [Keys -> KeyStates]
    /\ evid \subseteq Precommits
    /\ canon \in [Parents -> {"unknown", "canonical", "orphan"}]
    /\ claim2 \in {NONE, "C2", "S2"}
    /\ parent \in ParentStates
    /\ resHist \in [Traders -> {"Pending", "Realized", "Invalid", "Void"}]

\* P and G are non-economic: a position holds only a registered F or a
\* transition.
PrecommitNonEconomic ==
    \A tr \in Traders : slot[tr] \in {SlotNone, SlotS} \cup Fulfillments

\* ATOMIC, ALL OR NONE: E1 consumes RA exactly when it consumes RB.
FulfillmentAtomic == (E1 \in ConsumersOf(RA)) <=> (E1 \in ConsumersOf(RB))

\* Only a parent whose canonicality is established is consumed.
OnlyCanonicalParentsConsumed ==
    \A r \in Parents : ConsumersOf(r) # {} => canon[r] = "canonical"

\* An E1 cell whose route is objectively impossible is skipped, with no
\* "every leg final" premise (R7-17).
ObjectivelyImpossible(r) ==
    \/ Validation(P1) = "Invalid"
    \/ \E r2 \in LegsOf(P1) \ {r} : canon[r2] = "orphan"
    \/ IF r = RB THEN ConsumedSingle ELSE ConsumedByOtherRB
    \/ slot[T] = SlotS

ObjectiveRejectionImpliesSkipped ==
    \A k \in Keys : key[k] = E1 /\ ObjectivelyImpossible(k[1]) => Skipped(k)

\* Once a position resolves, its resolution never changes.
ResolutionPermanent ==
    \A tr \in Traders : resHist[tr] # "Pending" => Resolve(tr) = resHist[tr]

MismatchedParentNeverRealizes ==
    parent \in {"other", "none"} => Resolve(T) # "Realized"

PendingParentDecidesNothing ==
    ParentPending /\ Registered(T) /\ Validation(P1) # "Invalid" =>
        /\ Resolve(T) = "Pending"
        /\ \A r \in Parents : canon[r] # "orphan" => ~ArmIV

\* The fence: no claim at q + 1 before q holds a claim, and an unresolved
\* conditional position is never a predecessor (Section 22).
ContiguousPositions == claim2 # NONE => slot[T] # SlotNone
UnresolvedConditionalNeverPredecessor ==
    claim2 # NONE /\ Registered(T) => Resolve(T) # "Pending"

GenesisCanonicalOnlyIfCreationValid ==
    ConsumersOf(RB) # {} => CreationValidB

\* Stored is not valid; registered is not valid; Realized requires every
\* Core predicate.
RealizedRequiresValidSetup == Resolve(T) = "Realized" => SetupValidP1
\* Both stated against the FACT (TrueConformance), not the verifier's answer,
\* so a verifier that reads registration as conformance is caught.
RealizedRequiresConformance ==
    \A tr \in Traders : Resolve(tr) = "Realized" => TrueConformance(tr) = "Valid"
RegistrationIsNotConformance ==
    \A tr \in Traders : Registered(tr) /\ TrueConformance(tr) # "Valid" => Resolve(tr) # "Realized"
EarlyCellCannotCauseConsumption ==
    E1 \in ConsumersOf(RA) => Registered(T) /\ Validation(P1) = "Valid"
InvalidStoredNeverAdmitted ==
    \A k \in Keys : key[k] = E1 /\ Validation(P1) = "Invalid" => E1 \notin ConsumersOf(k[1])

\* R13-5, as quiescence: with evidence available and completers acting, a
\* registered F is not left Pending.
QuiescentFulfillmentResolved ==
    ~ProgressEnabled => \A tr \in Traders : Registered(tr) => Resolve(tr) # "Pending"

\* Witnesses never lock.
PolicyFulfillmentNeverLocks ==
    ~ProgressEnabled /\ ~RivalProgressEnabled => Registered(U) \/ ConsumersOf(RA) # {}

\* -----------------------------------------------------------------------------
\* NON-VACUITY AND CLAIMS EXPECTED TO BE FALSE. Listed only in configs that
\* must violate them: the counterexample is the witness.
\* -----------------------------------------------------------------------------
ParentArmNeverDecidesInvalid ==
    ~ /\ Registered(T)
      /\ parent \in {"other", "none"}
      /\ Validation(P1) # "Invalid"
      /\ Resolve(T) = "Invalid"

RegisteredValidFulfillmentNeverVoids ==
    \A tr \in Traders :
        /\ Registered(tr)
        /\ Truth(RegPrecommit(tr))
        /\ \A r \in covers[tr] : canon[r] # "orphan"
        => Resolve(tr) # "Void"

RouteNeverRealized == Resolve(T) # "Realized"

\* Early cell occupancy is reachable: a key holds E1 while T is unregistered.
EarlyCellNeverOccupied == ~(\E k \in Keys : key[k] = E1 /\ ~Registered(T))

\* A malformed F registers: the store keeps what it is given.
MalformedFulfillmentNeverRegisters == Registered(T) => TrueConformance(T) # "Invalid"

====
