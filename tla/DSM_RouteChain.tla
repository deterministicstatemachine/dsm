---------------------------- MODULE DSM_RouteChain ----------------------------
\* ROUTE-CHAIN FINALITY AT ONE CELL (storage spec §9, §12.6; DSM Amendment
\* A6; SoFi Amendment S4; dsm/src/route_chain.rs).
\*
\* A cell's route is R(K) = [r0, r1, r2, r3, r4] over the committed set; r0 is
\* the leader. A writer writes a value to the seats in route order, leader
\* first, and every copy after the leader carries the chain built so far: the
\* leader's arrival record and each later seat's. A seat that does not answer
\* is passed over (a NoResponse slot); the chain continues at the next seat.
\*
\*   LeaderHeld(x) == x is the first value that reached the leader
\*   Preserved(x)  == LeaderHeld(x) /\ at least one further valid link
\*   Final(x)      == LeaderHeld(x) /\ at least two further valid links
\*
\* Only a value with a valid leader link can have a valid further link: every
\* copy carries the leader's record, and the leader's record names the first
\* arrival. A node stores what it is given and removes nothing; it never reads
\* a chain and never decides one.
\*
\* This replaces the copy rule ("LeaderHeld /\ two other members hold x") the
\* successor-cell, fulfillment and reserve models used (G15). Those modules
\* take their finality from here.
\*
\* Beta scope. The loss rule, handover and retirement (MR-STOR-0122-0124) are
\* outside beta; what is checked here is the chain itself and what survives up
\* to two lost seats.
\*
\* MUTATIONS. `Mutation` switches in a wrong rule; every mutation config names
\* the invariant that must FAIL, so a model that passes a mutation is broken:
\*   "none"               the rule as specified
\*   "AnyArrivalLeads"    any value that reached the leader has a leader link
\*   "CountWithoutLeader" further links count without a valid leader link
\*   "NodeRemoves"        a seat may drop what it holds
------------------------------------------------------------------------------
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Values,    \* the values writers may write at the cell
          Route,     \* <<r0, r1, r2, r3, r4>>: distinct seats, r0 the leader
          Mutation   \* "none" or one of the mutations above

ASSUME Len(Route) = 5
ASSUME \A i, j \in 1..5 : i # j => Route[i] # Route[j]
ASSUME Mutation \in {"none", "AnyArrivalLeads", "CountWithoutLeader", "NodeRemoves"}

Seats  == {Route[i] : i \in 1..5}
Leader == Route[1]

VARIABLES
    arrivals,  \* the leader's arrivals at the cell, in order
    copies,    \* copies[i]: values whose copy seat Route[i] holds (i in 2..5)
    last,      \* last[x]: the route position x's chain has reached (0: not written)
    lost       \* seats lost

vars == <<arrivals, copies, last, lost>>

TypeOK ==
    /\ arrivals \in Seq(Values)
    /\ copies \in [2..5 -> SUBSET Values]
    /\ last \in [Values -> 0..5]
    /\ lost \subseteq Seats

Init ==
    /\ arrivals = <<>>
    /\ copies = [i \in 2..5 |-> {}]
    /\ last = [x \in Values |-> 0]
    /\ lost = {}

------------------------------------------------------------------------------
\* THE CHAIN, as a verifier evaluates it.

LeaderLink(x) ==
    IF Mutation = "AnyArrivalLeads"
    THEN \E i \in 1..Len(arrivals) : arrivals[i] = x
    ELSE Len(arrivals) > 0 /\ arrivals[1] = x

FurtherLinks(x) == {i \in 2..5 : x \in copies[i]}

ValidLinks(x) ==
    IF Mutation = "CountWithoutLeader"
    THEN Cardinality(FurtherLinks(x)) + (IF LeaderLink(x) THEN 1 ELSE 0)
    ELSE IF LeaderLink(x) THEN 1 + Cardinality(FurtherLinks(x)) ELSE 0

LeaderHeld(x) == ValidLinks(x) >= 1 /\ (Mutation = "CountWithoutLeader" \/ LeaderLink(x))
Preserved(x)  == ValidLinks(x) >= 2
Final(x)      == ValidLinks(x) >= 3

------------------------------------------------------------------------------
\* ACTIONS. A node never refuses a write; what a seat holds only grows.

\* A writer writes x to the leader. The leader appends it, first or not.
WriteLeader(x) ==
    /\ Leader \notin lost
    /\ last[x] = 0
    /\ arrivals' = Append(arrivals, x)
    /\ last' = [last EXCEPT ![x] = 1]
    /\ UNCHANGED <<copies, lost>>

\* The writer extends x's chain to route position i, past any seats that did
\* not answer. The copy carries the leader's record, which is a valid leader
\* link only for the first arrival; a loser's copy carries an invalid one, so
\* it is written but counts for nothing (it is not a FurtherLink of a valid
\* chain unless the mutation counts it).
Extend(x, i) ==
    /\ last[x] >= 1
    /\ i > last[x]
    /\ i \in 2..5
    /\ Route[i] \notin lost
    /\ (LeaderLink(x) \/ Mutation = "CountWithoutLeader")
    /\ copies' = [copies EXCEPT ![i] = @ \cup {x}]
    /\ last' = [last EXCEPT ![x] = i]
    /\ UNCHANGED <<arrivals, lost>>

\* A seat is lost (at most two, the loss bound of §12.6).
Lose(s) ==
    /\ s \in Seats \ lost
    /\ Cardinality(lost) < 2
    /\ lost' = lost \cup {s}
    /\ UNCHANGED <<arrivals, copies, last>>

\* MUTATION ONLY: a seat drops what it holds.
Remove(i, x) ==
    /\ Mutation = "NodeRemoves"
    /\ x \in copies[i]
    /\ copies' = [copies EXCEPT ![i] = @ \ {x}]
    /\ UNCHANGED <<arrivals, last, lost>>

Next ==
    \/ \E x \in Values : WriteLeader(x)
    \/ \E x \in Values, i \in 2..5 : Extend(x, i)
    \/ \E s \in Seats : Lose(s)
    \/ \E i \in 2..5, x \in Values : Remove(i, x)

Spec == Init /\ [][Next]_vars

------------------------------------------------------------------------------
\* INVARIANTS.

\* MR-STOR-0143: at most one value has a valid leader link at a cell, so at
\* most one value is preserved or final.
ChainUniqueness ==
    \A x, y \in Values : LeaderHeld(x) /\ LeaderHeld(y) => x = y

AtMostOneFinal ==
    \A x, y \in Values : Final(x) /\ Final(y) => x = y

\* The states nest: Final implies Preserved implies LeaderHeld.
StatesNest ==
    \A x \in Values : (Final(x) => Preserved(x)) /\ (Preserved(x) => LeaderHeld(x))

\* A final value is held by three seats, so with at most two lost at least one
\* holder of its chain survives (the durability the loss rule of §12.6 relies
\* on; the rule itself is outside beta).
FinalSurvivesTwoLosses ==
    \A x \in Values : Final(x) =>
        \/ Leader \notin lost
        \/ \E i \in FurtherLinks(x) : Route[i] \notin lost

\* MR-DSM-0270 / MR-STOR-0127: finality never reverts. Nothing a node does
\* (it only appends) and no loss changes a value's chain facts.
FinalityStable == [][\A x \in Values : Final(x) => Final(x)']_vars
LeaderHeldStable == [][\A x \in Values : LeaderHeld(x) => LeaderHeld(x)']_vars

==============================================================================
