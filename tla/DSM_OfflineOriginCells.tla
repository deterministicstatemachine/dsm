---- MODULE DSM_OfflineOriginCells ----
EXTENDS Naturals, Integers, FiniteSets, TLC

\* =============================================================================
\* OFFLINE STEPS FINAL AT THEIR ORIGIN CELLS: A RECEIVER SETTLES WITHOUT THE
\* PAYER, AND A RESTORED PAYER RESUMES WITHOUT ITS RECEIVERS.
\*
\* SCOPE. One payer's offline account, loaded with Alloc at its last online
\* boundary (root 0), its board, two receivers, and the origin cells: one cell
\* per account root, keyed by the root a step starts from. A cell's occupant is
\* the FIRST RECOGNIZED write; finality at the storage members is taken from
\* DSM_RouteChain and DSM_SofiSuccessorCells and is not re-modelled here: a
\* recognized first write is the occupant for good. Anyone holding a step may
\* write it: the step's own board signatures are the authority, the writer only
\* carries it.
\*
\* A step is [id, from, rcpt, amt, kind, sig, after]: sig is "board" (the board's
\* signatures), "online" (the payer's online key) or "none"; after marks a step
\* made after the restore. Its id is also the account root
\* it leads to, so roots are 0 (the boundary) and the step ids. The account's
\* allocation at a root is a software fold from the boundary (Bal); a step is
\* valid when it spends no more than the fold leaves at its starting root.
\*
\* THE BOARD. A genuine board signs one step per counter and only from its own
\* frontier (boardRoot), then moves to it; it checks no amount. A broken board
\* (BrokenBoard) signs from any root it has signed to before. A modified wallet
\* (ModifiedWallet) asks the board for steps the fold does not cover.
\*
\* THE RECEIVERS check the fold of every step from the boundary at receipt and
\* keep the steps they were carried. Online, a receiver writes them to their
\* cells and settles its payment only when every cell on the payment's path holds
\* exactly that path's step (identified by its signed content, not its bytes),
\* and none of them is unreadable.
\*
\* THE PAYER, online, unloads what its account holds; the unload counts only
\* when it and its ancestry hold their cells. Under option B (the design) an
\* unload is a board step like any other; OptionA leaves it to the online key,
\* from any root the payer knows.
\*
\* RESTORE drops the payer phone's knowledge of its steps. With BoardKeepsCopies
\* the board hands back every step it signed; without it the wallet walks the
\* cells from the boundary.
\*
\* HIDDEN models the privacy split: a cell shows only the board, the starting
\* root and the signatures over a sealed digest of the rest, so a reader can
\* check that a write is board-signed and keyed to its root, but cannot fold it
\* and so cannot skip an invalid occupant. Without HIDDEN a reader folds every
\* write and skips one that spends more than its root holds.
\*
\* FALSIFICATIONS. Each DSM_OfflineOriginCells_<Name>.cfg flips one constant
\* (or states a claim that must be false) and lists the invariant it must
\* violate.
\* =============================================================================

CONSTANTS
    Alloc,             \* the allocation the boundary loaded (2)
    MaxSteps,          \* bound on step ids
    Hidden,            \* the privacy split: readers cannot fold an occupant
    BrokenBoard,       \* [FALSE] the board signs from any root it signed to
    ModifiedWallet,    \* the payer's wallet asks for steps the fold does not cover
    BoardKeepsCopies,  \* the board keeps every step it signed and hands them back at restore
    JamPossible,       \* anyone can make a cell unreadable (liveness only)
    OptionA,           \* [FALSE] an unload is signed by the online key, not the board
    UnsignedCounts,    \* [FALSE] a step without the board's signatures is recognized (unsigned Settle)
    ByteIdentity,      \* [FALSE] an occupant is identified by its bytes, not its signed content
    RecognizeJunk,     \* [FALSE] bytes that are no step are recognized
    SettleWithoutCells,\* [FALSE] a receiver settles on the boundary alone, reading no cell
    ReplayAllowed      \* [FALSE] a receiver settles a payment twice or one not addressed to it

ASSUME Alloc \in Nat /\ MaxSteps \in Nat

Rcv == {"R1", "R2"}
ONLINE == "online"
\* Occupants are pairs <<id, encoding>>; step ids start at 1, so id 0 marks an
\* empty cell or junk.
NONE == <<0, "none">>
JUNK == <<0, "junk">>
Amounts == 1..(Alloc + 1)

VARIABLES
    S,            \* every step that exists: board-signed, or forged unsigned
    nextId,       \* the next step id (and root)
    boardRoot,    \* a genuine board's frontier
    payerRoot,    \* the root the payer's phone stands at
    payerKnows,   \* the steps the payer's phone holds
    copies,       \* the steps the board keeps (BoardKeepsCopies)
    restored,     \* the payer's phone has been wiped and restored
    held,         \* [Rcv -> step ids each receiver was carried]
    acc,          \* [Rcv -> payment step ids each receiver accepted offline]
    cell,         \* [0..MaxSteps -> NONE | JUNK | <<id, enc>>]
    jam,          \* roots whose cell cannot be read
    settled,      \* <<receiver, step id>> settled online
    settledTotal, \* value settled to receivers online
    credited,     \* unload step ids credited online
    unloaded      \* value unloaded to the payer online

vars == <<S, nextId, boardRoot, payerRoot, payerKnows, copies, restored, held, acc,
          cell, jam, settled, settledTotal, credited, unloaded>>

Roots == 0..MaxSteps
Ids == {s.id : s \in S}
StepOf(i) == CHOOSE s \in S : s.id = i

\* The account's allocation at a root: a fold from the boundary.
RECURSIVE Bal(_)
Bal(r) == IF r = 0 THEN Alloc ELSE Bal(StepOf(r).from) - StepOf(r).amt

\* The steps from the boundary to root r.
RECURSIVE Path(_)
Path(r) == IF r = 0 THEN {} ELSE {r} \cup Path(StepOf(r).from)

Valid(s) == s.amt >= 0 /\ s.amt <= Bal(s.from)
ChainValid(r) == \A j \in Path(r) : Valid(StepOf(j))

\* What a reader recognizes as a step written at the cell of its own root.
Recognized(s) ==
    /\ \/ s.sig = "board"
       \/ OptionA /\ s.sig = "online" /\ s.kind = "unload"
       \/ UnsignedCounts /\ s.sig = "none"
    /\ (Hidden \/ ChainValid(s.id))

\* An occupant holds step j: by signed content, or by exact bytes (fault).
Holds(j, occ) ==
    \/ occ = <<j, "o">>
    \/ ~ByteIdentity /\ occ = <<j, "a">>

PathHeld(r) == \A j \in Path(r) : Holds(j, cell[StepOf(j).from])
PathReadable(r) == \A j \in Path(r) : StepOf(j).from \notin jam

Init ==
    /\ S = {}
    /\ nextId = 1
    /\ boardRoot = 0
    /\ payerRoot = 0
    /\ payerKnows = {}
    /\ copies = {}
    /\ restored = FALSE
    /\ held = [r \in Rcv |-> {}]
    /\ acc = [r \in Rcv |-> {}]
    /\ cell = [r \in Roots |-> NONE]
    /\ jam = {}
    /\ settled = {}
    /\ settledTotal = 0
    /\ credited = {}
    /\ unloaded = 0

\* ---- the payer pays a receiver offline -------------------------------------
\* The board signs from the payer's root; a genuine board only from its own
\* frontier. The receiver takes the payment only if the fold covers its whole path.
NewStep(from, rcpt, amt, kind, sig) ==
    [id |-> nextId, from |-> from, rcpt |-> rcpt, amt |-> amt, kind |-> kind, sig |-> sig,
     after |-> restored]

BoardMay(from) == BrokenBoard \/ from = boardRoot

Pay(rv, a) ==
    /\ nextId <= MaxSteps
    /\ BoardMay(payerRoot)
    /\ ModifiedWallet \/ a <= Bal(payerRoot)
    /\ LET s == NewStep(payerRoot, rv, a, "spend", "board")
           \* The receiver folds the carried path and the payment itself.
           ok == ChainValid(payerRoot) /\ a <= Bal(payerRoot)
       IN /\ S' = S \cup {s}
          /\ nextId' = nextId + 1
          /\ boardRoot' = IF payerRoot = boardRoot THEN s.id ELSE boardRoot
          /\ payerRoot' = s.id
          /\ payerKnows' = payerKnows \cup {s.id}
          /\ copies' = IF BoardKeepsCopies THEN copies \cup {s.id} ELSE copies
          /\ held' = IF ok THEN [held EXCEPT ![rv] = @ \cup Path(payerRoot) \cup {s.id}] ELSE held
          /\ acc' = IF ok THEN [acc EXCEPT ![rv] = @ \cup {s.id}] ELSE acc
    /\ UNCHANGED <<restored, cell, jam, settled, settledTotal, credited, unloaded>>

\* ---- a broken board signs a second step from a root it already left --------
Fork(rv, a, r) ==
    /\ BrokenBoard
    /\ nextId <= MaxSteps
    /\ r \in {0} \cup {s.id : s \in {x \in S : x.sig = "board"}}
    /\ LET s == NewStep(r, rv, a, "spend", "board")
       IN /\ S' = S \cup {s}
          /\ nextId' = nextId + 1
          /\ copies' = IF BoardKeepsCopies THEN copies \cup {s.id} ELSE copies
          /\ held' = [held EXCEPT ![rv] = @ \cup Path(r) \cup {s.id}]
          \* The receiver folds the carried path and the payment itself.
          /\ acc' = IF ChainValid(r) /\ a <= Bal(r) THEN [acc EXCEPT ![rv] = @ \cup {s.id}] ELSE acc
    /\ UNCHANGED <<boardRoot, payerRoot, payerKnows, restored, cell, jam, settled,
                   settledTotal, credited, unloaded>>

\* ---- the payer unloads what its account holds ------------------------------
\* Option B: a board step from the board's frontier. OptionA: the online key,
\* from any root the payer's phone knows, the board untouched.
Unload(r) ==
    /\ nextId <= MaxSteps
    /\ IF OptionA THEN r \in {0} \cup payerKnows ELSE r = payerRoot /\ BoardMay(r)
    /\ Bal(r) > 0
    /\ LET s == NewStep(r, ONLINE, Bal(r), "unload", IF OptionA THEN "online" ELSE "board")
       IN /\ S' = S \cup {s}
          /\ nextId' = nextId + 1
          /\ boardRoot' = IF ~OptionA /\ r = boardRoot THEN s.id ELSE boardRoot
          /\ payerRoot' = s.id
          /\ payerKnows' = payerKnows \cup {s.id}
          /\ copies' = IF BoardKeepsCopies /\ ~OptionA THEN copies \cup {s.id} ELSE copies
    /\ UNCHANGED <<restored, held, acc, cell, jam, settled, settledTotal, credited, unloaded>>

\* The unload counts online once it and its ancestry hold their cells.
Credit(u) ==
    /\ u \in payerKnows
    /\ StepOf(u).kind = "unload"
    /\ u \notin credited
    /\ PathHeld(u)
    /\ PathReadable(u)
    /\ credited' = credited \cup {u}
    /\ unloaded' = unloaded + StepOf(u).amt
    /\ UNCHANGED <<S, nextId, boardRoot, payerRoot, payerKnows, copies, restored, held,
                   acc, cell, jam, settled, settledTotal>>

\* ---- anyone holding a step writes it to its cell ---------------------------
Holdings == payerKnows \cup copies \cup UNION {held[r] : r \in Rcv}

Write(i, enc) ==
    /\ i \in Holdings
    /\ LET s == StepOf(i) IN
       /\ cell[s.from] = NONE
       /\ Recognized(s)
       /\ cell' = [cell EXCEPT ![s.from] = <<i, enc>>]
    /\ UNCHANGED <<S, nextId, boardRoot, payerRoot, payerKnows, copies, restored, held,
                   acc, jam, settled, settledTotal, credited, unloaded>>

\* Bytes that are no step, sent to any cell. They occupy only if recognized.
WriteJunk(r) ==
    /\ RecognizeJunk
    /\ cell[r] = NONE
    /\ cell' = [cell EXCEPT ![r] = JUNK]
    /\ UNCHANGED <<S, nextId, boardRoot, payerRoot, payerKnows, copies, restored, held,
                   acc, jam, settled, settledTotal, credited, unloaded>>

\* An unsigned step built by anyone from a root it knows (an unsigned Settle).
Forge(r) ==
    /\ nextId <= MaxSteps
    /\ r \in {0} \cup Holdings
    /\ LET s == NewStep(r, ONLINE, 0, "settle", "none")
       IN /\ S' = S \cup {s}
          /\ nextId' = nextId + 1
          /\ held' = [held EXCEPT !["R2"] = @ \cup {s.id}]
    /\ UNCHANGED <<boardRoot, payerRoot, payerKnows, copies, restored, acc, cell, jam,
                   settled, settledTotal, credited, unloaded>>

Jam(r) ==
    /\ JamPossible
    /\ r \notin jam
    /\ jam' = jam \cup {r}
    /\ UNCHANGED <<S, nextId, boardRoot, payerRoot, payerKnows, copies, restored, held,
                   acc, cell, settled, settledTotal, credited, unloaded>>

\* ---- a receiver settles its payment online, without the payer --------------
Settle(rv, i) ==
    /\ IF ReplayAllowed THEN i \in held[rv] /\ StepOf(i).kind = "spend"
                        ELSE i \in acc[rv] /\ <<rv, i>> \notin settled
    /\ SettleWithoutCells \/ (PathHeld(i) /\ PathReadable(i))
    /\ settled' = settled \cup {<<rv, i>>}
    /\ settledTotal' = settledTotal + StepOf(i).amt
    /\ UNCHANGED <<S, nextId, boardRoot, payerRoot, payerKnows, copies, restored, held,
                   acc, cell, jam, credited, unloaded>>

\* ---- the payer's phone is wiped and the wallet restored --------------------
RECURSIVE WalkEnd(_, _)
WalkEnd(r, n) ==
    IF n = 0 THEN r
    ELSE LET c == cell[r] IN
         IF c \in {NONE, JUNK} THEN r
         ELSE IF StepOf(c[1]).from = r THEN WalkEnd(c[1], n - 1) ELSE r

Restore ==
    /\ ~restored
    /\ restored' = TRUE
    /\ payerRoot' = IF BoardKeepsCopies THEN boardRoot ELSE WalkEnd(0, MaxSteps)
    /\ payerKnows' = IF BoardKeepsCopies THEN copies ELSE Path(WalkEnd(0, MaxSteps))
    /\ UNCHANGED <<S, nextId, boardRoot, copies, held, acc, cell, jam, settled,
                   settledTotal, credited, unloaded>>

\* The bounded model may run out of steps to take; nothing is owed after that.
Idle == UNCHANGED vars

Next ==
    \/ \E rv \in Rcv, a \in Amounts : Pay(rv, a)
    \/ \E rv \in Rcv, a \in Amounts, r \in Roots : Fork(rv, a, r)
    \/ \E r \in Roots : Unload(r)
    \/ \E u \in Ids : Credit(u)
    \/ \E i \in Ids, enc \in {"o", "a"} : Write(i, enc)
    \/ \E r \in Roots : WriteJunk(r)
    \/ \E r \in Roots : Forge(r)
    \/ \E r \in Roots : Jam(r)
    \/ \E rv \in Rcv, i \in Ids : Settle(rv, i)
    \/ Restore
    \/ Idle

Spec == Init /\ [][Next]_vars

\* =============================================================================
\* INVARIANTS
\* =============================================================================

TypeOK ==
    /\ nextId \in 1..(MaxSteps + 1)
    /\ boardRoot \in Roots
    /\ payerRoot \in Roots
    /\ settledTotal \in Nat
    /\ unloaded \in Nat

\* No value is created: what receivers settle plus what the payer unloads never
\* exceeds what the boundary loaded.
NoCounterfeit == settledTotal + unloaded <= Alloc

\* A receiver never accepts a payment the fold does not cover.
AcceptedIsCovered == \A rv \in Rcv : \A i \in acc[rv] : ChainValid(i)

\* With a genuine board, no accepted payment's path is ever held by anything
\* other than its own steps: the payer's later steps, a forged step, a
\* re-encoded copy or junk can never take its cell.
NoHonestBlock ==
    ~BrokenBoard =>
        \A rv \in Rcv : \A i \in acc[rv] : \A j \in Path(i) :
            LET c == cell[StepOf(j).from] IN c = NONE \/ Holds(j, c)

\* The same, with no assumption about the board: what a broken board can do.
NoHonestBlockAny ==
    \A rv \in Rcv : \A i \in acc[rv] : \A j \in Path(i) :
        LET c == cell[StepOf(j).from] IN c = NONE \/ Holds(j, c)

\* A restored payer stands where its board stands, so its next step is one the
\* board will sign: it needs nobody to come back.
RestoreResumes == (restored /\ ~BrokenBoard) => payerRoot = boardRoot

\* Every settled payment was accepted by its receiver and covered by the fold.
SettledWasAccepted == \A p \in settled : p[2] \in acc[p[1]]

\* ---- reachability claims, each stated as a must-be-false invariant ---------
\* Some receiver settles without the payer ever unloading or coming back.
NoSettleWithoutPayer == ~(settledTotal > 0 /\ credited = {})
\* An occupant the fold does not cover blocks an accepted payment.
NoInvalidTwinBlocks ==
    ~(\E rv \in Rcv : \E i \in acc[rv] : \E j \in Path(i) :
        LET c == cell[StepOf(j).from] IN
        c \notin {NONE, JUNK} /\ ~Holds(j, c) /\ ~ChainValid(c[1]))
\* A covered occupant blocks an accepted payment.
NoValidTwinBlocks ==
    ~(\E rv \in Rcv : \E i \in acc[rv] : \E j \in Path(i) :
        LET c == cell[StepOf(j).from] IN
        c \notin {NONE, JUNK} /\ ~Holds(j, c) /\ ChainValid(c[1]))
\* No payment the restored wallet makes ever settles.
NoSettleAfterRestore == ~(\E p \in settled : StepOf(p[2]).after)
\* An accepted payment cannot be settled because a cell on its path is jammed.
NoJamBlocksSettle ==
    ~(\E rv \in Rcv : \E i \in acc[rv] : PathHeld(i) /\ ~PathReadable(i))
====
