------------------------- MODULE DSM_ReceiptWriteSet -------------------------
\* A RECEIPT PROVES ITS STEP'S WHOLE WRITE SET (DSM §9, §30, §67-68;
\* dsm/src/verification/receipt_verification.rs `verify_receipt_state`;
\* dsm/src/merkle/batch_fold.rs).
\*
\* An offline-bearer spend moves three leaves of its author's device root at
\* once: the relationship tip, the anchor counter and the offline allocation it
\* draws from (§9: the counter and the value source are inside the root). A
\* receiver judges the author's receipt of the spend against the author's root
\* before it, and from then on the author's root is the receipt's child root —
\* so a leaf the receipt does not prove to have moved is a leaf the world keeps
\* seeing unmoved.
\*
\* The author here is unconstrained: every receipt it can form over the leaves
\* is submitted, honest or not. The verifier's rule is the only defence:
\*   - the writes are exactly the leaves the operation implies (a bearer spend:
\*     relationship, anchor, allocation), each once;
\*   - every pre-value is the one the author's root holds (the pre-root fold);
\*   - every post-value is the one the verifier derives: the tip's successor,
\*     the counter plus one, the allocation less the operation's amount.
\* Then the child root is the fold of those writes, and nothing else moves.
\*
\* The symbolic abstractions: a write's pre-value matching the author's root
\* stands for the batch fold from `parent_root` (lean4/DSMStepTransition.lean,
\* `fold_sound`); the tip derivation stands for `relationship_chain_tip_v2`.
\*
\* MUTATIONS. `Mutation` switches in a wrong verifier; every mutation config
\* names the property that must FAIL, so a model that passes one is broken:
\*   "none"                   the rule as specified
\*   "RelationshipOnlyCheck"  the verifier checks the relationship write alone
\*                            and accepts whatever else the receipt says moved
\*   "OnePathRule"            a receipt carries one relationship path and
\*                            nothing else (the wire before field 22): the
\*                            honest bearer spend cannot be proven — the
\*                            production bug this model was written for
\*                            (`HonestSpendAcceptable` fails).
EXTENDS Naturals, FiniteSets

CONSTANTS Peers,       \* the counterparties the author spends to
          InitAlloc,   \* the offline allocation loaded before the spends
          Amounts,     \* the amounts a spend may name
          MaxSteps,    \* how many accepted steps the model explores
          Mutation     \* "none" or one of the mutations above

ASSUME InitAlloc \in Nat /\ Amounts \subseteq (Nat \ {0}) /\ MaxSteps \in Nat
ASSUME Mutation \in {"none", "RelationshipOnlyCheck", "OnePathRule"}

Kinds == {"rel", "anchor", "alloc"}
BearerWrites == Kinds

VARIABLES
    rel,       \* rel[p]: the author's relationship tip toward p
    counter,   \* the anchor counter u
    alloc,     \* the offline allocation's amount
    spent,     \* the value receivers credited from accepted receipts
    steps,     \* how many receipts were accepted
    accepted   \* the accepted receipts

vars == <<rel, counter, alloc, spent, steps, accepted>>

Receipt == [peer: Peers, writes: SUBSET Kinds, amount: Amounts,
            relPre: Nat, relPost: Nat, ctrPre: Nat, ctrPost: Nat,
            allocPre: Nat, allocPost: Nat]

TypeOK ==
    /\ rel \in [Peers -> 0..MaxSteps]
    /\ counter \in 0..MaxSteps
    /\ alloc \in 0..InitAlloc
    /\ spent \in Nat
    /\ steps \in 0..MaxSteps
    /\ accepted \subseteq Receipt

Init ==
    /\ rel = [p \in Peers |-> 0]
    /\ counter = 0
    /\ alloc = InitAlloc
    /\ spent = 0
    /\ steps = 0
    /\ accepted = {}

------------------------------------------------------------------------------
\* THE VERIFIER. A receipt's pre-values are what the author's root holds for
\* the leaves it names (the fold from `parent_root` fails otherwise, in every
\* mode); the tip is always recomputed. What differs is which writes the
\* verifier requires and whether it derives their post-values.

PreHolds(r) ==
    /\ r.relPre = rel[r.peer]
    /\ ("anchor" \in r.writes => r.ctrPre = counter)
    /\ ("alloc" \in r.writes => r.allocPre = alloc)

Derived(r) ==
    /\ r.relPost = r.relPre + 1
    /\ r.ctrPost = r.ctrPre + 1
    /\ r.amount <= r.allocPre
    /\ r.allocPost = r.allocPre - r.amount

Holds(r) ==
    /\ PreHolds(r)
    /\ "rel" \in r.writes
    /\ r.relPost = r.relPre + 1
    /\ CASE Mutation = "none" ->
              r.writes = BearerWrites /\ Derived(r)
         [] Mutation = "RelationshipOnlyCheck" ->
              TRUE
         [] Mutation = "OnePathRule" ->
              r.writes = {"rel"}

\* The author's root after an accepted receipt: the leaves it proves moved hold
\* their post-values; the others hold what they held.
Accept(r) ==
    /\ rel' = [rel EXCEPT ![r.peer] = r.relPost]
    /\ counter' = IF "anchor" \in r.writes THEN r.ctrPost ELSE counter
    /\ alloc' = IF "alloc" \in r.writes THEN r.allocPost ELSE alloc
    /\ spent' = spent + r.amount
    /\ steps' = steps + 1
    /\ accepted' = accepted \cup {r}

------------------------------------------------------------------------------
\* THE AUTHOR. Any receipt over the leaves, with its pre-values read from its
\* own root (a receipt that lies about them is refused in every mode) and its
\* post-values chosen: moved or not, debited or not.

Submit(p, W, a, ctrPost, allocPost) ==
    LET r == [peer |-> p, writes |-> W, amount |-> a,
              relPre |-> rel[p], relPost |-> rel[p] + 1,
              ctrPre |-> counter, ctrPost |-> ctrPost,
              allocPre |-> alloc, allocPost |-> allocPost]
    IN /\ steps < MaxSteps
       /\ Holds(r)
       /\ Accept(r)

AnySubmit ==
    \E p \in Peers, W \in SUBSET Kinds, a \in Amounts,
       ctrPost \in {counter, counter + 1},
       allocPost \in {x \in {alloc, alloc - 1, alloc - 2} : x >= 0} :
        Submit(p, W, a, ctrPost, allocPost)

\* The honest spend: all three writes, each derived.
HonestSpend ==
    \E p \in Peers, a \in Amounts :
        /\ a <= alloc
        /\ Submit(p, BearerWrites, a, counter + 1, alloc - a)

Next == AnySubmit \/ HonestSpend

Spec == Init /\ [][Next]_vars /\ WF_vars(HonestSpend)

------------------------------------------------------------------------------
\* PROPERTIES

\* Every accepted receipt proved exactly the leaves a bearer spend writes.
ClosedWriteSet ==
    \A r \in accepted : r.writes = BearerWrites

\* Value leaves the allocation only as receivers credit it.
AllocationConserved == alloc + spent = InitAlloc

\* The anchor counter moves with every accepted step, and only then.
CounterMovesWithRoot == counter = steps

\* The verifier refuses no honest spend: whenever the allocation can pay one
\* (and the model has a step left), the honest receipt of it is acceptable.
\* The state-predicate form of `fold_complete` (lean4/DSMStepTransition.lean).
HonestSpendAcceptable ==
    (steps < MaxSteps /\ \E a \in Amounts : a <= alloc) => ENABLED HonestSpend

\* An honest bearer spend is eventually proven: a receipt proving the whole
\* write set is accepted.
HonestBearerStepAccepted ==
    <>(\E r \in accepted : r.writes = BearerWrites)

=============================================================================
