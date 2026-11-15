--------------------------- MODULE DSM_WriteLock ---------------------------
(***************************************************************************)
(* DSM Amendments A34 and A37: every storage node runs one check on every *)
(* write to an inbox, and nothing else.                                   *)
(*                                                                         *)
(* Every inbox is a route bound to one lock: a write is taken there only  *)
(* when the address is its route bound to the lock it carries, the lock   *)
(* signed its grant, and the granted key signed it. A relationship's      *)
(* FIRST inbox is bound to the writer's first-inbox lock, the key its     *)
(* directory entry publishes, lock and write key at once (A37); every     *)
(* LATER inbox to the recipient's write lock (A34). The node keeps no     *)
(* state for any inbox, so nothing that arrives first fixes anything.     *)
(*                                                                         *)
(* Writes reach the nodes in any order and any node may miss any of them  *)
(* (a delivery reaches its quorum, not every member). Signatures are not  *)
(* forged: a grant is signed by a lock only when the lock's holder issued *)
(* it (`Granted`), or the lock is an attacker's own key. A write is signed *)
(* by the key its writer holds.                                           *)
(*                                                                         *)
(* Rust twin: `dsm::core::relationship_write_grant::verify_spool_write`   *)
(* and the node's `spool_append`. Lean twin:                              *)
(* lean4/DSMRelationshipWriteLock.lean.                                   *)
(*                                                                         *)
(* `CheckLock` switches the check's binding of an address to the lock a   *)
(* write carries; the falsification configs turn it off and TLC shows the *)
(* invariants it guards violated, at a recipient's inbox and at a first   *)
(* inbox.                                                                 *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Nodes,          \* the storage set's members
    Routes,         \* inbox routes
    Keys,           \* every public key: locks and write keys
    HonestLocks,    \* locks whose grants only their holders sign
    FirstLocks,     \* writers' published first-inbox locks (honest; each grants only itself)
    AttackerKeys,   \* keys an attacker holds: it signs grants and writes with them
    WriterKeys,     \* keys whose holders write
    Granted,        \* the <<lock, key>> grants the honest locks issued
    CheckLock       \* the node binds an address to the write's lock

Addr == {<<r, l>> : r \in Routes, l \in Keys}

Write == [route : Routes, lock : Keys, granted : Keys, grantSigner : Keys, signer : Keys]

(* A write someone can make: its writer signs with a key it holds, and its  *)
(* grant is one an honest lock issued or one an attacker's key signs.       *)
Producible(w) ==
    /\ w.signer \in WriterKeys
    /\ \/ <<w.grantSigner, w.granted>> \in Granted
       \/ w.grantSigner \in AttackerKeys

VARIABLES stored
vars == <<stored>>

TypeOK == stored \in [Nodes -> SUBSET (Addr \X Write)]

Init == stored = [n \in Nodes |-> {}]

(* The node's check of `w` at `a`. It reads the two and nothing a node holds. *)
Accept(a, w) ==
    /\ a[1] = w.route
    /\ CheckLock => a[2] = w.lock
    /\ w.grantSigner = w.lock
    /\ w.signer = w.granted

Take(n, a, w) ==
    /\ Producible(w)
    /\ <<a, w>> \notin stored[n]
    /\ Accept(a, w)
    /\ stored' = [stored EXCEPT ![n] = @ \cup {<<a, w>>}]

(* Every write any node can still take is taken: the run is over. The model *)
(* is finite, so every behavior ends here.                                  *)
Settled ==
    /\ \A n \in Nodes, a \in Addr, w \in Write :
          ~(Producible(w) /\ <<a, w>> \notin stored[n] /\ Accept(a, w))
    /\ UNCHANGED vars

Next == (\E n \in Nodes, a \in Addr, w \in Write : Take(n, a, w)) \/ Settled

Spec == Init /\ [][Next]_vars

(* The grants the configs model: the honest lock "L" granted key "K", and   *)
(* the first-inbox lock "F" grants only itself (a TLC configuration file    *)
(* cannot spell a tuple).                                                   *)
MCGranted == {<<"L", "K">>, <<"F", "F">>}

(* A writer's own write at its first inbox on route `r`: lock and write key *)
(* at once, granting itself.                                                *)
OwnWrite(r, f) == [route |-> r, lock |-> f, granted |-> f, grantSigner |-> f, signer |-> f]

-----------------------------------------------------------------------------
(* Every write any node took at an honest lock's inbox is signed by a key  *)
(* that lock granted.                                                      *)
LockedHoldsOnlyGranted ==
    \A n \in Nodes : \A e \in stored[n] :
        e[1][2] \in HonestLocks => <<e[1][2], e[2].signer>> \in Granted

(* Every write any node took at a first inbox is its writer's own: signed  *)
(* by the first-inbox lock the address is bound to.                        *)
FirstInboxOnlyItsWriter ==
    \A n \in Nodes : \A e \in stored[n] :
        e[1][2] \in FirstLocks => e[2].signer = e[1][2]

(* Whatever any node took before, every node takes the writer's own write  *)
(* at its first inbox: nothing that arrived first closes it.               *)
FirstInboxNeverClosed ==
    \A n \in Nodes : \A r \in Routes : \A f \in FirstLocks :
        <<<<r, f>>, OwnWrite(r, f)>> \in stored[n] \/ Accept(<<r, f>>, OwnWrite(r, f))

(* Non-vacuity: an honest grantee's write is taken at its lock's inbox.     *)
GrantedWriteReachable ==
    ~ \E n \in Nodes : \E e \in stored[n] :
        e[1][2] \in HonestLocks /\ e[2].signer # e[1][2]
=============================================================================
