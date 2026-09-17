---- MODULE DSM_SofiFulfillment ----
EXTENDS Naturals, FiniteSets, TLC

\* =============================================================================
\* SOFI V8: ONE UNILATERAL TRADER OPERATION, RUN CONCURRENTLY.
\*
\* SCOPE. A route is one trader operation P -> G_1..G_n -> F -> realization
\* (plan revision 10.3, F2-F4). This module owns the BEHAVIOUR of that
\* operation while it interleaves with everything else that can touch its DLV
\* parents: a rival trader consuming a parent between the witnesses and F, the
\* trader abandoning P or doing something else at its position, completers
\* writing cells and the outcome, validation evidence arriving late, a parent
\* being orphaned, and a descendant claim at q + 1.
\*
\* Storage is at the level of REGISTERED FACTS: a key is Empty, Dead or final
\* with one E; a trader position holds one registered claim; the route outcome
\* is Complete or Abort. That these are well-defined quorum facts -- write-once,
\* one final value per key, one registered claim per position, C = C_q, Dead
\* never final -- is universal algebra over the five members and belongs to
\* Lean (lean4/DSMSofiSuccessorCells.lean). The member-level behaviour of the
\* same registers -- partial reads, records, attempts, crashes, equivocation --
\* is DSM_SofiSuccessorCells.tla. Neither is re-derived here.
\*
\* THE MODEL
\*   Parents   RA (vault A: keys at attempts 0 and 1), RB (vault B: attempt 0);
\*             whether each is canonical is settled once, by its own lineage
\*   P1        trader T, route over RA and RB, external commitment E1
\*   P2        trader U, single leg on RA, external commitment E2
\*   F         a precommit plus its attempt at RA, fixed at exercise time
\*   T may instead make an incompatible transition "S" at its position, and may
\*   claim position q + 1 ("C2" conditional, "S2" ordinary).
\*   T0        the claim at p that P1 names as its trader parent: either an
\*             ordinary single-root claim, or a conditional SoFi claim whose
\*             branch selection is decided later, by p's own resolution
\*
\* RULINGS ENCODED
\*   R9/R12   P and G are non-economic; G is deterministic and never locks.
\*   R10-2    F registers even after a parent is lost; it then resolves Void.
\*   R10-3    RouteImpossible: (i) Invalid, (ii) orphan, (iii') a parent consumed
\*            by another E -- none gated on Complete (R7-17).
\*   R13-5    a registered F resolves under evidence availability.
\*   R14-1    Void requires RouteValidation = Valid; missing evidence is Pending.
\*   P15-3    a conditional trader parent adds two rungs BELOW registration and
\*   R17-3    above any route result: q is Pending while p is, and Invalid once
\*            p selected another root or none. Arm (iv) of RouteImpossible is
\*            the same fact, and it needs no validation evidence.
\*
\* LIVENESS AS QUIESCENCE. Every action here is bounded, so every behaviour is
\* finite. Under weak fairness on the required (honest-completer) actions, a
\* behaviour ends only in a state where none of them is enabled. "A registered
\* F resolves" is therefore the INVARIANT Quiescent => Resolved, checked over
\* every reachable state; it runs in the standard gate rather than an opt-in
\* liveness pass. Trader actions are discretionary and never required.
\*
\* FALSIFICATIONS. Each DSM_SofiFulfillment_<Name>.cfg flips one constant below
\* (or states a claim that must be false) and lists exactly the invariant it
\* must violate; tools/vertical_validation/src/tla_runner.rs gates the verdict
\* and tla/README.md tabulates them.
\* =============================================================================

CONSTANTS
    ValidP1,                           \* [TRUE] RouteValidation(P1) once evidence exists
    ValidP2,                           \* [TRUE] RouteValidation(P2) once evidence exists
    CreationValidB,                    \* [TRUE] vault B's creation validated
    MaxStep,                           \* DFID depth budget (runner reads it)
    EvidenceMayBeWithheld,             \* [FALSE] R13-5 assumption removed
    PrecommitAsExercise,               \* [FALSE] storing P occupies the position
    LockingPolicyFulfillments,         \* [FALSE] a foreign witness refuses F ingress
    PartialFulfillment,                \* [FALSE] F registers without every witness
    CompleteWithoutCanonicalParents,   \* [FALSE] consumption ignores orphaned parents
    ThirdPartyAbort,                   \* [FALSE] Abort without objective failure
    LaterKeyAbort,                     \* [FALSE] Abort justified by another attempt's key
    CompleteRejectedNotSkipped,        \* [FALSE] arm (i) gated on Complete
    OrphanNotSkipped,                  \* [FALSE] arm (ii) gated on Complete
    StaleLegNotSkipped,                \* [FALSE] arm (iii') gated on Complete
    VoidBeforeValidation,              \* [FALSE] Void without RouteValidation = Valid
    ParentBranchIgnored,               \* [FALSE] which branch T0 selected is not checked
    PendingParentIsImpossible,         \* [FALSE] an undecided T0 is treated as terminal
    OrdinaryClaimBypassesFence,        \* [FALSE] fence applied to conditional claims only
    DescendantValidatedByStorage,      \* [FALSE] q + 1 validated on storage resolution
    RegisteredGenesisAccepted,         \* [FALSE] the walk starts from a stored genesis
    TraderOnlyCompletion               \* [FALSE] only the trader may complete

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

Fulfillments == {<<P1, 0>>, <<P1, 1>>, <<P2, 0>>, <<P2, 1>>}
PrecommitOf(f) == f[1]
AttemptAt(f, r) == IF r = RA THEN f[2] ELSE 0
KeyOf(f, r) == <<r, AttemptAt(f, r)>>
Keys == {<<RA, 0>>, <<RA, 1>>, <<RB, 0>>}
KeyStates == {"empty", "dead"} \cup Commitments

\* The claim at p that P1 was built on. "single" is an ordinary claim, whose
\* root P conformance already pinned at ingress. The rest are one conditional
\* claim: "open" before p resolves, then the branch it selected -- "taken" is
\* the root P built on, "other" is the opposite branch, "none" is p resolving
\* Invalid and selecting no root at all.
ParentStates == {"single", "open", "taken", "other", "none"}

\* Position values share one shape so TLC can compare them.
SlotNone == <<"none", 0>>
SlotS == <<"S", 0>>
SlotPrecommit == <<"precommit", 0>>

VARIABLES
    pStored,   \* content-addressed precommits: no position
    gStored,   \* content-addressed witnesses <<precommit, parent>>
    slot,      \* [Traders -> registered claim at q]: SlotNone, SlotS, or an F
    covers,    \* [Traders -> parents the registered F's witness set covers]
    key,       \* [Keys -> KeyStates] storage finality of each successor key
    out,       \* outcome register K_out of T's registered route F
    evid,      \* precommits whose validation evidence is available
    canon,     \* [Parents -> unknown | canonical | orphan], from the parent's own lineage
    online,    \* traders able to act (matters only under TraderOnlyCompletion)
    claim2,    \* T's claim at q + 1
    parent,    \* the claim at p that P1 names: ParentStates
    resHist    \* [Traders -> first non-Pending resolution observed]

vars == <<pStored, gStored, slot, covers, key, out, evid, canon, online, claim2,
          parent, resHist>>

\* =============================================================================
\* THE VERIFIER: validation, the walk, consumption, resolution
\* =============================================================================

Validation(p) ==
    IF p \notin evid THEN "Unavailable"
    ELSE IF Truth(p) THEN "Valid" ELSE "Invalid"

Registered(tr) == slot[tr] \in Fulfillments
RegPrecommit(tr) == PrecommitOf(slot[tr])
FKeys(tr) == {KeyOf(slot[tr], r) : r \in covers[tr]}

\* THE TRADER PARENT (P15-3, R17-3). A trader may build P on a conditional
\* parent before that parent resolves, because the storage fence only requires
\* p to be storage-resolved: it is guessing which branch p will take. The guess
\* is settled here, never at ingress.
\*
\* While the parent is open both predicates are false, so an undecided parent
\* decides nothing: it neither consumes nor skips.
ParentPending == parent = "open"
ParentImpossible ==
    \/ parent \in {"other", "none"}
    \/ PendingParentIsImpossible /\ ParentPending
ParentCompatible == ParentBranchIgnored \/ parent \in {"single", "taken"}

\* The walk starts only from an accepted genesis (F10).
WalkStart(r) == r = RA \/ CreationValidB \/ RegisteredGenesisAccepted

\* A trader whose registered F names key k (cells are admissible only for it).
Writers(k) == {tr \in Traders : Registered(tr) /\ k[1] \in covers[tr] /\ KeyOf(slot[tr], k[1]) = k}

CompleteNow == out = "Complete"
AbortedAt(k) == out = "Abort" /\ Registered(T) /\ k \in FKeys(T)

\* No precommit other than P1 names RB, so RB is never consumed by another E.
ConsumedByOtherRB == \E k \in Keys : k[1] = RB /\ key[k] \in Commitments \ {E1}

\* The route arms for an E1 cell at parent r, as the implementation evaluates
\* them. Arm (iii') for a cell at RA looks at RB, and for a cell at RB looks at
\* RA's single-leg consumer; nothing refers back to the cell's own parent.
ArmI == Validation(P1) = "Invalid"
ArmII(r) == \E r2 \in LegsOf(P1) \ {r} : canon[r2] = "orphan"
ArmIVAt0 == ~ParentBranchIgnored /\ ParentImpossible

RouteRejectedAtRA0 ==
    \/ ArmI /\ (CompleteRejectedNotSkipped => CompleteNow)
    \/ ArmII(RA) /\ (OrphanNotSkipped => CompleteNow)
    \/ ConsumedByOtherRB /\ (StaleLegNotSkipped => CompleteNow)
    \/ ArmIVAt0
    \/ AbortedAt(<<RA, 0>>)

\* The attempt-0 key at RA, which every later attempt at RA depends on.
Skipped0 ==
    \/ key[<<RA, 0>>] = "dead"
    \/ key[<<RA, 0>>] = E2 /\ Validation(P2) = "Invalid"
    \/ key[<<RA, 0>>] = E1 /\ RouteRejectedAtRA0

LiveAt(r, a) == r = RB \/ a = 0 \/ Skipped0

ConsumedSingle ==
    /\ Registered(U)
    /\ Validation(P2) = "Valid"
    /\ canon[RA] = "canonical"
    /\ LiveAt(RA, AttemptAt(slot[U], RA))
    /\ key[KeyOf(slot[U], RA)] = E2

ArmIII(r) == IF r = RB THEN ConsumedSingle ELSE ConsumedByOtherRB

\* Arm (iv): T0 is terminal on another branch, or on none. It refers to no
\* evidence, so a stranded cell of such an operation is skippable while
\* RouteValidation is still Unavailable. It creates no Void -- the position is
\* Invalid by rung 2 -- and exists only to stop an impossible operation
\* stranding a DLV successor key.
ArmIV == ~ParentBranchIgnored /\ ParentImpossible

RouteImpossibleAt(r) ==
    \/ ArmI /\ (CompleteRejectedNotSkipped => CompleteNow)
    \/ ArmII(r) /\ (OrphanNotSkipped => CompleteNow)
    \/ ArmIII(r) /\ (StaleLegNotSkipped => CompleteNow)
    \/ ArmIV

Skipped(k) ==
    IF k = <<RA, 0>> THEN Skipped0
    ELSE \/ key[k] = "dead"
         \/ key[k] = E2 /\ Validation(P2) = "Invalid"
         \/ key[k] = E1 /\ (RouteImpossibleAt(k[1]) \/ AbortedAt(k))

ConsumedRoute ==
    /\ Registered(T)
    /\ RegPrecommit(T) = P1
    /\ Validation(P1) = "Valid"
    /\ ParentCompatible
    /\ \A r \in covers[T] :
          /\ CompleteWithoutCanonicalParents \/ canon[r] = "canonical"
          /\ WalkStart(r)
          /\ LiveAt(r, AttemptAt(slot[T], r))
          /\ key[KeyOf(slot[T], r)] = E1
    /\ Cardinality(covers[T]) >= 2 => CompleteNow

ConsumersOf(r) ==
    (IF ConsumedRoute /\ r \in covers[T] THEN {E1} ELSE {})
    \cup (IF r = RA /\ ConsumedSingle THEN {E2} ELSE {})

Realized(tr) == IF tr = T THEN ConsumedRoute ELSE ConsumedSingle

StorageResolvedF(tr) ==
    /\ \A k \in FKeys(tr) : key[k] # "empty"
    /\ RegPrecommit(tr) = P1 => out # NONE

VoidEvidence(tr) ==
    LET e == EOf(RegPrecommit(tr)) IN
    \/ \E k \in FKeys(tr) : key[k] = "dead" \/ key[k] \in Commitments \ {e}
    \/ \E r \in covers[tr] : canon[r] = "orphan" \/ ConsumersOf(r) \ {e} # {}
    \/ tr = T /\ out = "Abort"

\* The resolution ladder (F2). Rungs 1 and 2 are the trader parent (P15-3);
\* they sit above every route result, because a position built on a branch the
\* parent never took is Invalid whatever its own legs did. Step 5 carries
\* R14-1. Only T has a modelled parent; U's single leg stands alone.
Resolve(tr) ==
    IF ~Registered(tr) THEN "Pending"
    ELSE IF tr = T /\ ~ParentBranchIgnored /\ ~PendingParentIsImpossible
            /\ ParentPending
         THEN "Pending"
    ELSE IF tr = T /\ ~ParentBranchIgnored /\ ParentImpossible THEN "Invalid"
    ELSE IF Realized(tr) THEN "Realized"
    ELSE IF Validation(RegPrecommit(tr)) = "Invalid" THEN "Invalid"
    ELSE IF /\ (VoidBeforeValidation \/ Validation(RegPrecommit(tr)) = "Valid")
            /\ StorageResolvedF(tr)
            /\ VoidEvidence(tr)
         THEN "Void"
    ELSE "Pending"

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
    /\ UNCHANGED <<gStored, covers, key, out, evid, canon, online, claim2, parent>>

\* Anyone computes and publishes a witness for a leg of a stored P.
StoreG(p, r) ==
    /\ p \in pStored
    /\ r \in LegsOf(p)
    /\ <<p, r>> \notin gStored
    /\ gStored' = gStored \cup {<<p, r>>}
    /\ Hist
    /\ UNCHANGED <<pStored, slot, covers, key, out, evid, canon, online, claim2, parent>>

RequiredWitnesses(p) == IF PartialFulfillment THEN {RA} ELSE LegsOf(p)

RegisterGuard(f) ==
    LET p == PrecommitOf(f) IN
    /\ p \in pStored
    /\ slot[Trader(p)] = SlotNone
    /\ \A r \in RequiredWitnesses(p) : <<p, r>> \in gStored
    \* F conformance: a later attempt needs its predecessor storage-resolved.
    /\ AttemptAt(f, RA) = 1 => key[<<RA, 0>>] # "empty"
    \* A prepare lock would refuse F while another trader's witness is outstanding.
    /\ LockingPolicyFulfillments =>
          ~\E g \in gStored : g[1] # p /\ g[2] \in LegsOf(p) /\ ~Registered(Trader(g[1]))

\* The trader signs F and it registers: K_ful and C_q in one transaction.
\* Ingress never asks whether a parent is still unconsumed (R10-2).
Register(f) ==
    LET p == PrecommitOf(f) IN
    /\ RegisterGuard(f)
    /\ slot' = [slot EXCEPT ![Trader(p)] = f]
    /\ covers' = [covers EXCEPT ![Trader(p)] = {r \in LegsOf(p) : <<p, r>> \in gStored}]
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, key, out, evid, canon, online, claim2, parent>>

\* An incompatible trader transition at q.
Transition ==
    /\ slot[T] = SlotNone
    /\ slot' = [slot EXCEPT ![T] = SlotS]
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, covers, key, out, evid, canon, online, claim2, parent>>

\* A completer writes a registered F's E into its key. Two registered writers
\* at one key may split it Dead.
WriteKey(k, tr) ==
    /\ key[k] = "empty"
    /\ tr \in Writers(k)
    /\ CompleterOK(tr)
    /\ key' = [key EXCEPT ![k] = EOf(RegPrecommit(tr))]
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, out, evid, canon, online, claim2, parent>>

SplitGuard(k) ==
    /\ key[k] = "empty"
    /\ Cardinality({EOf(RegPrecommit(tr)) : tr \in Writers(k)}) >= 2
    /\ \E tr \in Writers(k) : CompleterOK(tr)

SplitKey(k) ==
    /\ SplitGuard(k)
    /\ key' = [key EXCEPT ![k] = "dead"]
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, out, evid, canon, online, claim2, parent>>

CompleteGuard ==
    /\ Registered(T) /\ RegPrecommit(T) = P1 /\ out = NONE /\ CompleterOK(T)
    /\ \A k \in FKeys(T) : key[k] = E1

AbortGuard ==
    /\ Registered(T) /\ RegPrecommit(T) = P1 /\ out = NONE /\ CompleterOK(T)
    /\ \/ ThirdPartyAbort
       \/ \E k \in FKeys(T) : key[k] \in {"dead", E2}
       \/ LaterKeyAbort /\ \E k \in Keys :
             k[1] \in covers[T] /\ k \notin FKeys(T) /\ key[k] \in {"dead", E2}

WriteOutcome(o) ==
    /\ IF o = "Complete" THEN CompleteGuard ELSE AbortGuard
    /\ out' = o
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, key, evid, canon, online, claim2, parent>>

PublishEvidence(p) ==
    /\ p \in pStored
    /\ p \notin evid
    /\ evid' = evid \cup {p}
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, key, out, canon, online, claim2, parent>>

\* The parent's own lineage settles whether it is canonical. Exogenous, once.
SettleParent(r, c) ==
    /\ canon[r] = "unknown"
    /\ canon' = [canon EXCEPT ![r] = c]
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, key, out, evid, online, claim2, parent>>

\* p resolves and its branch selection becomes known, exogenously and once —
\* the same shape as SettleParent. "taken" is the root P built on, "other" the
\* opposite branch, "none" a position that resolved Invalid and selected no
\* root at all.
SelectParentBranch(b) ==
    /\ parent = "open"
    /\ parent' = b
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, key, out, evid, canon, online, claim2>>

GoOffline(tr) ==
    /\ TraderOnlyCompletion
    /\ tr \in online
    /\ online' = online \ {tr}
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, key, out, evid, canon, claim2, parent>>

StorageResolvedT ==
    \/ slot[T] = SlotS
    \/ Registered(T) /\ StorageResolvedF(T)

\* Storage ingress for ANY claim kind at q + 1 is fenced on q.
ClaimNext(kind) ==
    /\ claim2 = NONE
    /\ slot[T] # SlotNone
    /\ StorageResolvedT \/ (OrdinaryClaimBypassesFence /\ kind = "S2")
    /\ claim2' = kind
    /\ Hist
    /\ UNCHANGED <<pStored, gStored, slot, covers, key, out, evid, canon, online, parent>>

\* Nothing left to do. Quiescence is checked by the invariants below, not by
\* TLC's deadlock detection.
Idle == UNCHANGED vars

Next ==
    \/ \E p \in Precommits : StoreP(p)
    \/ \E p \in Precommits, r \in Parents : StoreG(p, r)
    \/ \E f \in Fulfillments : Register(f)
    \/ Transition
    \/ \E k \in Keys, tr \in Traders : WriteKey(k, tr)
    \/ \E k \in Keys : SplitKey(k)
    \/ \E o \in {"Complete", "Abort"} : WriteOutcome(o)
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
    /\ out = NONE
    /\ evid = {}
    /\ canon = [r \in Parents |-> "unknown"]
    /\ online = Traders
    /\ claim2 = NONE
    \* Both trader-parent kinds are initial states, so one run covers an
    \* ordinary parent and a conditional one whose branch is still open.
    /\ parent \in {"single", "open"}
    /\ resHist = [tr \in Traders |-> "Pending"]

Spec == Init /\ [][Next]_vars

\* =============================================================================
\* QUIESCENCE: the required (honest-completer) actions
\* =============================================================================

ProgressEnabled ==
    \/ \E r \in Parents : canon[r] = "unknown"
    \/ ParentPending
    \/ \E k \in Keys, tr \in Traders : key[k] = "empty" /\ tr \in Writers(k) /\ CompleterOK(tr)
    \/ CompleteGuard
    \/ AbortGuard
    \/ ~EvidenceMayBeWithheld /\ \E p \in pStored : p \notin evid

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
    /\ out \in {NONE, "Complete", "Abort"}
    /\ evid \subseteq Precommits
    /\ canon \in [Parents -> {"unknown", "canonical", "orphan"}]
    /\ claim2 \in {NONE, "C2", "S2"}
    /\ parent \in ParentStates
    /\ resHist \in [Traders -> {"Pending", "Realized", "Invalid", "Void"}]

\* P and G are non-economic: a position holds only a registered F or a
\* transition, and no key holds the E of an unregistered precommit.
PrecommitNonEconomic ==
    /\ \A tr \in Traders : slot[tr] \in {SlotNone, SlotS} \cup Fulfillments
    /\ \A k \in Keys : key[k] \in Commitments =>
          \E tr \in Traders : Registered(tr) /\ EOf(RegPrecommit(tr)) = key[k]

\* ATOMIC, ALL OR NONE: E1 consumes RA exactly when it consumes RB.
FulfillmentAtomic == (E1 \in ConsumersOf(RA)) <=> (E1 \in ConsumersOf(RB))

\* Only a parent whose canonicality is established is consumed.
OnlyCanonicalParentsConsumed ==
    \A r \in Parents : ConsumersOf(r) # {} => canon[r] = "canonical"

\* Abort is written only when one of the F's OWN keys failed objectively.
AbortOnlyOnObjectiveFailure ==
    out = "Abort" => \E k \in FKeys(T) : key[k] \in {"dead", E2}

\* An E1 cell whose route is objectively impossible is skipped, with no
\* Complete premise (R7-17). The right-hand side is the implementation's walk.
ObjectivelyImpossible(r) ==
    \/ Validation(P1) = "Invalid"
    \/ \E r2 \in LegsOf(P1) \ {r} : canon[r2] = "orphan"
    \/ IF r = RB THEN ConsumedSingle ELSE ConsumedByOtherRB

ObjectiveRejectionImpliesSkipped ==
    \A k \in Keys : key[k] = E1 /\ ObjectivelyImpossible(k[1]) => Skipped(k)

\* R14-1: once a position resolves, its resolution never changes.
ResolutionPermanent ==
    \A tr \in Traders : resHist[tr] # "Pending" => Resolve(tr) = resHist[tr]

\* P15-3 rung 2 / arm (iv): a route built on a branch the parent never took can
\* never realize, whatever its own legs did.
MismatchedParentNeverRealizes ==
    parent \in {"other", "none"} => Resolve(T) # "Realized"

\* P15-3 rung 1: an undecided parent decides nothing. It may not push q to a
\* terminal answer, and it may not make the route impossible on its own.
PendingParentDecidesNothing ==
    ParentPending /\ Registered(T) /\ Validation(P1) # "Invalid" =>
        /\ Resolve(T) = "Pending"
        /\ \A r \in Parents : canon[r] # "orphan" => ~ArmIV

\* The storage fence, for every claim kind.
ContiguousPositions == claim2 # NONE => slot[T] # SlotNone

AtMostOneStorageUnresolvedFulfillmentPerLineage ==
    claim2 # NONE /\ Registered(T) => StorageResolvedF(T)

\* The Core local fence: q + 1 is validated ancestry only over a selected root.
ValidatedAtNext ==
    /\ claim2 # NONE
    /\ \/ slot[T] = SlotS
       \/ Registered(T) /\ IF DescendantValidatedByStorage
                            THEN StorageResolvedF(T)
                            ELSE Resolve(T) \in {"Realized", "Void"}

SpeculativeDescendantsNeverCanonicalUnderInvalidBranch ==
    ValidatedAtNext /\ Registered(T) => Resolve(T) \in {"Realized", "Void"}

GenesisCanonicalOnlyIfCreationValid ==
    ConsumersOf(RB) # {} => CreationValidB

\* R13-5, as quiescence: with evidence available and completers acting, a
\* registered F is not left Pending.
QuiescentFulfillmentResolved ==
    ~ProgressEnabled => \A tr \in Traders : Registered(tr) => Resolve(tr) # "Pending"

\* Witnesses never lock: when the rival and the completers have nothing left
\* to do, the rival is registered or RA is consumed -- whatever an abandoned
\* precommit's witnesses say.
PolicyFulfillmentNeverLocks ==
    ~ProgressEnabled /\ ~RivalProgressEnabled => Registered(U) \/ ConsumersOf(RA) # {}

\* -----------------------------------------------------------------------------
\* NON-VACUITY: the trader-parent arm decides a position by itself.
\* DSM_SofiFulfillment_ParentArmReachable.cfg expects this to be FALSE.
ParentArmNeverDecidesInvalid ==
    ~ /\ Registered(T)
      /\ parent \in {"other", "none"}
      /\ Validation(P1) # "Invalid"
      /\ Resolve(T) = "Invalid"

\* -----------------------------------------------------------------------------
\* CLAIMS EXPECTED TO BE FALSE. Listed only in configs that must violate them:
\* the counterexample is the witness.
\* -----------------------------------------------------------------------------

\* GuaranteedSuccessClaim: a registered, valid fulfillment whose parents stay
\* canonical never Voids. False under contention without a lock (R9-5).
RegisteredValidFulfillmentNeverVoids ==
    \A tr \in Traders :
        /\ Registered(tr)
        /\ Truth(RegPrecommit(tr))
        /\ \A r \in covers[tr] : canon[r] # "orphan"
        => Resolve(tr) # "Void"

\* Non-vacuity: the route can realize.
RouteNeverRealized == Resolve(T) # "Realized"

====
