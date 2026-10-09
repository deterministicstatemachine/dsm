---- MODULE DSM_NativeReserveRelease ----
EXTENDS Naturals, FiniteSets, Sequences, TLC

\* =============================================================================
\* THE NATIVE ERA RESERVE: ONE LINEAGE, RELEASED LEADER FIRST, REPLICATED
\* EVERYWHERE (Part IX §51; rebuild step R4; owner ruling 2026-09-20).
\*
\* SCOPE. One network's native reserve at its head state R_n (remaining units,
\* generation n) and the ONE cell where its successor is decided,
\* K(reserve, R_n), replicated across the frozen five-member set. Claimants
\* write releases naming themselves as recipient; anyone writes garbage; a
\* member keeps whatever it is given and decides nothing. Core recognizes,
\* resolves leader first, and advances the reserve by exactly the amount the
\* final release names. This module owns what happens at the MEMBERS and at
\* the reserve's accounting while claimants, hostile callers, outages and the
\* background carry interleave.
\*
\* TWO UNIVERSES (as in DSM_SofiSuccessorCells). Raw bytes at a member are one
\* universe; a release that verifies AND is the successor of the state Core
\* validated is the other. Recognition is the only way across: a release that
\* releases more than remains (RB below), or bytes that are no release (G),
\* never occupy the cell, never finalize and never move the reserve, however
\* early they arrived and however many members hold them.
\*
\* THE ONE TRANSITION. remaining' = remaining - amount, generation' = n + 1,
\* recipient credited exactly amount. There is no arm that raises `remaining`
\* (MintArm is a FAULT), no arm that moves units to a creator (CreatorBackout
\* is a FAULT), and the recipient is the claimant that signed the release
\* (RecipientSubstitution is a FAULT):
\*
\*   Supply = remaining + SUM balances                    at every state
\*   FaucetClaim(A, x)  =>  balance[A] += x
\*
\* TWO PROPERTIES, KEPT APART (owner ruling). Finality is leader first:
\*   LeaderHeld(x) == x is the first recognized object at the leader
\*   Final(x)      == LeaderHeld(x) /\ two OTHER members hold x
\* and nothing more — a release final on three members is exposed to its
\* recipient at once (Advance). Replication is all-member: anyone may carry
\* the final release to every remaining member, in the background, and an
\* unavailable non-leader member never blocks finality (AllMemberFinality is
\* a FAULT). Five copies would not make the decision more authoritative: the
\* leader already determines the cell; the additional copies are durability.
\*
\* THE MODEL
\*   members     the leader L of the cell is a fixed position of S (the seed
\*               binds the reserve and R_n, never availability); one
\*               distinguished non-leader A is explicit (it can be down, and
\*               the carry reaches it later); the three other members are
\*               interchangeable copies, held as a count per value
\*   values      RA (claimant A's release of 1), RC (claimant C's release of
\*               1), RB (claimant B's release of 2 — more than the reserve
\*               holds, so unrecognized), G (bytes no recognition rebuilds)
\*   reserve     Supply = 1, so exactly one release ever advances it; the
\*               race between RA and RC at the leader is the interesting one
\*   accounts    A, B, C and the Creator, who is never a claimant
\*
\* FALSIFICATIONS. Each DSM_NativeReserveRelease_<Name>.cfg flips one constant
\* below (or states a claim that must be false) and lists exactly the
\* invariant it must violate; tools/vertical_validation/src/tla_runner.rs
\* gates the verdict and tla/README.md tabulates them.
\* =============================================================================

CONSTANTS
    MaxStep,                 \* depth budget (the runner reads it; this model is finite)
    CountWithoutLeader,      \* [FALSE] finality counted over any three holders
    AvailabilityLeader,      \* [FALSE] the leader is whoever is reachable
    AllMemberFinality,       \* [FALSE] finality waits for every member
    OverdraftRecognized,     \* [FALSE] recognition accepts a release of more than remains
    MintArm,                 \* [FALSE] a transition that raises `remaining`
    CreatorBackout,          \* [FALSE] a transition that moves units to the creator
    RecipientSubstitution    \* [FALSE] the release credits someone other than its claimant

ASSUME MaxStep \in Nat /\ MaxStep >= 1

Supply == 1
RA == "RA"
RC == "RC"
RB == "RB"
G  == "G"
Values == {RA, RC, RB, G}
Countable == {RA, RC, RB}            \* what the three copy members may hold
Amount(v) == IF v = RB THEN 2 ELSE 1
Claimant(v) == IF v = RA THEN "A" ELSE IF v = RC THEN "C" ELSE "B"
Accounts == {"A", "B", "C", "Creator"}
NONE == "none"

L == "L"
A == "A"

VARIABLES
    leaderSeq,   \* what the leader holds at the cell, in arrival order
    altSeq,      \* what member A holds, in arrival order
    counts,      \* value -> how many of the three other members hold it (0..3)
    upL, upA,    \* availability of the leader and of member A
    remaining,   \* units the reserve still holds
    released,    \* whether the reserve advanced past R_0
    balance,     \* account -> units credited
    wonBy        \* the claimant whose release advanced the reserve, or NONE

vars == <<leaderSeq, altSeq, counts, upL, upA, remaining, released, balance, wonBy>>

\* ---------------------------------------------------------------------------
\* Recognition and the leader-first facts
\* ---------------------------------------------------------------------------

Recognized(v) == v \in {RA, RC} \/ (OverdraftRecognized /\ v = RB)

\* The leader of the cell: the committed position L, unless the fault lets
\* availability choose.
Lead == IF AvailabilityLeader /\ ~upL THEN A ELSE L
LeadSeq == IF Lead = L THEN leaderSeq ELSE altSeq

RECURSIVE FirstRecognized(_)
FirstRecognized(s) ==
    IF s = << >> THEN NONE
    ELSE IF Recognized(Head(s)) THEN Head(s) ELSE FirstRecognized(Tail(s))

Winner == FirstRecognized(LeadSeq)
LeaderHeld(v) == Winner = v

InSeq(v, s) == \E i \in 1..Len(s) : s[i] = v

\* Copies: members other than the leader that hold v.
Copies(v) ==
    (IF Lead = L THEN (IF InSeq(v, altSeq) THEN 1 ELSE 0)
                 ELSE (IF InSeq(v, leaderSeq) THEN 1 ELSE 0))
    + (IF v \in Countable THEN counts[v] ELSE 0)

Holders(v) == Copies(v) + (IF InSeq(v, LeadSeq) THEN 1 ELSE 0)

Final(v) ==
    IF CountWithoutLeader THEN Recognized(v) /\ Holders(v) >= 3
    ELSE IF AllMemberFinality THEN LeaderHeld(v) /\ Copies(v) >= 4
    ELSE LeaderHeld(v) /\ Copies(v) >= 2

\* ---------------------------------------------------------------------------
\* Actions
\* ---------------------------------------------------------------------------

\* Anyone writes any value to the leader; a member keeps everything it is
\* given, in arrival order (a value already held is not held twice here,
\* which loses nothing: a duplicate never changes what is first, or held).
WriteLeader(v) ==
    /\ upL /\ ~InSeq(v, leaderSeq)
    /\ leaderSeq' = Append(leaderSeq, v)
    /\ UNCHANGED <<altSeq, counts, upL, upA, remaining, released, balance, wonBy>>

WriteAlt(v) ==
    /\ upA /\ ~InSeq(v, altSeq)
    /\ altSeq' = Append(altSeq, v)
    /\ UNCHANGED <<leaderSeq, counts, upL, upA, remaining, released, balance, wonBy>>

\* One of the three copy members takes v (a write, or the background carry —
\* the member cannot tell, and neither can this model).
WriteOther(v) ==
    /\ v \in Countable /\ counts[v] < 3
    /\ counts' = [counts EXCEPT ![v] = @ + 1]
    /\ UNCHANGED <<leaderSeq, altSeq, upL, upA, remaining, released, balance, wonBy>>

CrashL == upL /\ upL' = FALSE /\ UNCHANGED <<leaderSeq, altSeq, counts, upA, remaining, released, balance, wonBy>>
RecoverL == ~upL /\ upL' = TRUE /\ UNCHANGED <<leaderSeq, altSeq, counts, upA, remaining, released, balance, wonBy>>
CrashA == upA /\ upA' = FALSE /\ UNCHANGED <<leaderSeq, altSeq, counts, upL, remaining, released, balance, wonBy>>
RecoverA == ~upA /\ upA' = TRUE /\ UNCHANGED <<leaderSeq, altSeq, counts, upL, remaining, released, balance, wonBy>>

\* Core advances the reserve by the final release: remaining' = remaining -
\* amount, the recipient (the claimant) credited exactly amount. The
\* construction predicate `amount <= remaining` is the recognition boundary;
\* OverdraftRecognized removes it.
Recipient(v) == IF RecipientSubstitution THEN "B" ELSE Claimant(v)
Advance(v) ==
    /\ ~released
    /\ Final(v)
    /\ (OverdraftRecognized \/ Amount(v) <= remaining)
    /\ released' = TRUE
    /\ remaining' = IF Amount(v) <= remaining THEN remaining - Amount(v) ELSE 0
    /\ balance' = [balance EXCEPT ![Recipient(v)] = @ + Amount(v)]
    /\ wonBy' = Claimant(v)
    /\ UNCHANGED <<leaderSeq, altSeq, counts, upL, upA>>

\* FAULT: an arm that raises the reserve.
Mint ==
    /\ MintArm
    /\ remaining' = remaining + 1
    /\ UNCHANGED <<leaderSeq, altSeq, counts, upL, upA, released, balance, wonBy>>

\* FAULT: an arm that moves units to the creator without a release.
Withdraw ==
    /\ CreatorBackout
    /\ remaining >= 1
    /\ remaining' = remaining - 1
    /\ balance' = [balance EXCEPT !["Creator"] = @ + 1]
    /\ UNCHANGED <<leaderSeq, altSeq, counts, upL, upA, released, wonBy>>

Next ==
    \/ \E v \in Values : WriteLeader(v) \/ WriteAlt(v) \/ WriteOther(v) \/ Advance(v)
    \/ CrashL \/ RecoverL \/ CrashA \/ RecoverA
    \/ Mint \/ Withdraw

Init ==
    /\ leaderSeq = << >>
    /\ altSeq = << >>
    /\ counts = [v \in Countable |-> 0]
    /\ upL = TRUE /\ upA = TRUE
    /\ remaining = Supply
    /\ released = FALSE
    /\ balance = [a \in Accounts |-> 0]
    /\ wonBy = NONE

Spec == Init /\ [][Next]_vars

\* ---------------------------------------------------------------------------
\* Invariants
\* ---------------------------------------------------------------------------

Sum(f) == f["A"] + f["B"] + f["C"] + f["Creator"]

TypeOK ==
    /\ leaderSeq \in Seq(Values) /\ Len(leaderSeq) <= 4
    /\ altSeq \in Seq(Values) /\ Len(altSeq) <= 4
    /\ counts \in [Countable -> 0..3]
    /\ upL \in BOOLEAN /\ upA \in BOOLEAN
    /\ remaining \in Nat
    /\ released \in BOOLEAN
    /\ balance \in [Accounts -> Nat]
    /\ wonBy \in {NONE, "A", "B", "C"}

\* Supply = remaining + SUM balances, at every state.
Conservation == Supply = remaining + Sum(balance)

\* No valid reserve transition mints: nothing was ever credited beyond what
\* the reserve gave up.
NoValidReserveTransitionMints == Sum(balance) <= Supply

\* The reserve is anchored to the network, owned by nobody.
NoCreatorBackout == balance["Creator"] = 0

\* FaucetClaim(A, x) => recipient = A: the release's claimant is credited.
RecipientIsClaimant == released => balance[wonBy] >= 1

\* A release only ever leaves by a release: remaining + released units.
ReleaseAccounting == remaining + (IF released THEN 1 ELSE 0) = Supply

\* Finality without the deterministic leader is impossible.
FinalRequiresLeader == \A v \in Values : Final(v) => LeaderHeld(v)

AtMostOneFinal == Cardinality({v \in Values : Final(v)}) <= 1

\* The leader is the committed position; availability never chooses it.
LeaderFromCommittedSet == Lead = L

\* Unrecognized bytes — garbage, and a release of more than remains — never
\* occupy the cell and never finalize.
UnrecognizedBytesNeverOccupy == \A v \in Values : ~Recognized(v) => ~LeaderHeld(v) /\ ~Final(v)

\* Three holders — the leader and two others — is finality; an unavailable
\* non-leader member never blocks it.
ThreeHoldersIsFinal == \A v \in Values : LeaderHeld(v) /\ Copies(v) >= 2 => Final(v)
UnavailableNonLeaderNeverBlocks ==
    \A v \in Values : ~upA /\ LeaderHeld(v) /\ counts[v] >= 2 => Final(v)

\* Additional replicas never alter the winner: the winner is a function of
\* the leader's read alone.
ReplicasDoNotAlterTheWinner ==
    \A v \in Values : Recognized(v) /\ Copies(v) = 4 /\ ~LeaderHeld(v) => ~Final(v)

\* ---------------------------------------------------------------------------
\* Reachability claims (each must be VIOLATED by its config)
\* ---------------------------------------------------------------------------

NeverReleased == ~released
NeverAllHold == ~(released /\ InSeq(wonBy, <<"A", "C">>) /\ \E v \in {RA, RC} :
                    Claimant(v) = wonBy /\ InSeq(v, leaderSeq) /\ InSeq(v, altSeq) /\ counts[v] = 3)
NeverLostAtLeader == ~(\E v \in {RA, RC} : LeaderHeld(v) /\ \E u \in {RA, RC} : u # v /\ InSeq(u, leaderSeq))

====
