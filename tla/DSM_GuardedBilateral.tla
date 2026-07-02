---- MODULE DSM_GuardedBilateral ----
\* ===========================================================================
\* Relationship-scoped bilateral model: why "two receivers, same parent"
\* cannot arise in online DSM.
\*
\* Two structural facts, both encoded directly:
\*
\*   (1) Every counterparty relationship is its own straight, linear hash
\*       chain (paper Sec 6). Candidates carry NO key field; the consumption
\*       key is DERIVED: DerivedKey(c) == <<c.rel, c.parent>> (paper Def 27,
\*       Def 33, Rule 2). A parent under relationship r is not replayable
\*       under q, even when the chains reuse the same node names.
\*
\*   (2) The topology is bilateral. A relationship step has exactly ONE
\*       receiver: the counterparty of that relationship. There is no second
\*       independent acceptor of the same relationship parent in online DSM,
\*       so each relationship is modeled with a single acceptance locus
\*       (cons[r], led[r]). Online acceptance is the receiver's own frontier
\*       and proof checks (paper Def 55); no co-signing round is part of the
\*       online path. The only setting where one spendable object is
\*       PRESENTED to multiple distinct receivers is offline bearer mode,
\*       which is governed by the fused anchor, the pending lock against
\*       conflicting offline initiation (Def 56), the co-signed precommit of
\*       the offline anchor design, and reconciliation (Sec 29, Thm 14).
\*       None of that is needed for the online claim and none of it is
\*       modeled here.
\*
\* The companion WF instance deliberately commits an attempted fork: two
\* candidates on the same (relationship, parent) with different successors.
\* TLC proves NoSameParentFork across ALL relationships in every interleaving:
\* equal keys force equal relationship (scoping), a relationship has one
\* receiver (bilateral), and that receiver's linearity admits one realization
\* per parent. The structure-removed contrast (DSM_GuardedMC_BilateralFork)
\* deletes the derived keys and the single-receiver topology, and only then
\* does the fork appear.
\* ===========================================================================
EXTENDS Naturals, FiniteSets

CONSTANTS
    Rel,        \* relationship identifiers (model values), one straight chain each
    Node,       \* chain node names; may be REUSED across relationships
    Candidate   \* records [rel : Rel, parent : Node, succ : Node,
                \*          bid : Nat, guard : BOOLEAN]  (no key field: derived)

VARIABLES
    cons,       \* cons[r]: consumption keys consumed by relationship r's receiver
    led         \* led[r]: receipts accepted by relationship r's receiver

Vars == <<cons, led>>

\* Derived resource consumption key (paper Def 27/33, Rule 2): committed parent
\* state and relationship identity, never discretionary branch input.
DerivedKey(c) == <<c.rel, c.parent>>

KeyT     == Rel \X Node
ReceiptT == [rel : Rel, parent : Node, succ : Node, key : KeyT, bid : Nat]

Receipt(c) == [rel |-> c.rel, parent |-> c.parent, succ |-> c.succ,
               key |-> DerivedKey(c), bid |-> c.bid]

\* The relationship's receiver accepts a fulfilled candidate whose derived key
\* it has not consumed (paper Def 41 conjuncts, Def 55 acceptance; frontier
\* adjacency is orthogonal to the scoping claim and omitted to keep the state
\* space minimal). Delivery order across relationships is adversarial.
Accept(c) ==
    /\ c \in Candidate
    /\ c.guard = TRUE
    /\ DerivedKey(c) \notin cons[c.rel]
    /\ cons' = [cons EXCEPT ![c.rel] = @ \cup {DerivedKey(c)}]
    /\ led'  = [led  EXCEPT ![c.rel] = @ \cup {Receipt(c)}]

Init ==
    /\ cons = [r \in Rel |-> {}]
    /\ led  = [r \in Rel |-> {}]

Next == \E c \in Candidate : Accept(c)

Spec == Init /\ [][Next]_Vars

TypeOK ==
    /\ cons \in [Rel -> SUBSET KeyT]
    /\ led  \in [Rel -> SUBSET ReceiptT]

\* Rule 2 / Def 33 as an invariant: every accepted receipt's key is the derived
\* key of its own relationship and parent. Name reuse across chains cannot
\* collide because the relationship identity is inside the key.
KeysDerivedAndScoped ==
    \A r \in Rel : \A x \in led[r] :
        /\ x.rel = r
        /\ x.key = <<x.rel, x.parent>>

\* Per-relationship linearity at the single receiver: one realized successor
\* per parent (paper Prop 11 at this receiver).
LocalHistoryUnique ==
    \A r \in Rel : \A x, y \in led[r] :
        (x.parent = y.parent) => x = y

\* Paper Sec 6: a parent under relationship r is not replayable under q. With
\* derived keys this is structural; stated so TLC witnesses it directly.
CrossRelKeyDisjoint ==
    \A r, q \in Rel : \A x \in led[r] : \A y \in led[q] :
        (x.key = y.key) => r = q

\* The headline claim, quantified across the WHOLE system: no two accepted
\* receipts anywhere consume the same key toward different successors. Equal
\* keys force equal relationship, a relationship has one receiver, and that
\* receiver realizes at most once per parent. Same-parent forks are
\* unconstructible online.
NoSameParentFork ==
    \A r, q \in Rel : \A x \in led[r] : \A y \in led[q] :
        (x.key = y.key) => x.succ = y.succ

=============================================================================
