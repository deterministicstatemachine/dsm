--------------------------- MODULE DSM_WriteLock ---------------------------
(***************************************************************************)
(* DSM Amendment A34: every storage node runs one check on every write to *)
(* an inbox, and nothing else.                                            *)
(*                                                                         *)
(* A relationship's FIRST inbox is the open address of its route: the     *)
(* first write a node takes there fixes the key, the writer's own (lock   *)
(* and write key at once), and every later write there must be under it.  *)
(* Every LATER inbox is the route bound to the recipient's lock: a write  *)
(* is taken there only when the address is its route bound to the lock it *)
(* carries, the lock signed its grant, and the granted key signed it. The *)
(* node keeps no state for a lock-bound inbox.                            *)
(*                                                                         *)
(* Writes reach the nodes in any order and any node may miss any of them  *)
(* (a delivery reaches its quorum, not every member). Signatures are not  *)
(* forged: a grant is signed by a lock only when the lock's holder issued *)
(* it (`Granted`), or the lock is an attacker's own key. A write is signed *)
(* by the key its writer holds.                                           *)
(*                                                                         *)
(* Rust twin: `dsm::core::relationship_write_grant::verify_spool_write`   *)
(* and the node's `spool_insert_locked` / `spool_append`. Lean twin:      *)
(* lean4/DSMRelationshipWriteLock.lean.                                   *)
(*                                                                         *)
(* `CheckLock` and `CheckFixed` switch the two halves of the check; the   *)
(* falsification configs turn one off and TLC shows the invariant it      *)
(* guards violated.                                                       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Nodes,          \* the storage set's members
    Routes,         \* inbox routes
    Keys,           \* every public key: locks and write keys
    HonestLocks,    \* recipients' locks, whose grants only their holders sign
    AttackerKeys,   \* keys an attacker holds: it signs grants and writes with them
    WriterKeys,     \* keys whose holders write
    Granted,        \* the <<lock, key>> grants the honest locks issued
    CheckLock,      \* the node binds a lock-bound address to the write's lock
    CheckFixed      \* the node holds a first inbox to the key its first write fixed

None == "none"

FirstAddr == {<<"first", r>> : r \in Routes}
LockedAddr == {<<"locked", r, l>> : r \in Routes, l \in Keys}
Addr == FirstAddr \cup LockedAddr

Write == [route : Routes, lock : Keys, granted : Keys, grantSigner : Keys, signer : Keys]

(* A write someone can make: its writer signs with a key it holds, and its  *)
(* grant is one an honest lock issued, one an attacker's key signs, or a    *)
(* writer's grant of its own key (a first inbox's self-granted write).      *)
Producible(w) ==
    /\ w.signer \in WriterKeys
    /\ \/ <<w.grantSigner, w.granted>> \in Granted
       \/ w.grantSigner \in AttackerKeys
       \/ (w.grantSigner = w.granted /\ w.granted \in WriterKeys)

VARIABLES fixed, stored
vars == <<fixed, stored>>

TypeOK ==
    /\ fixed \in [Nodes -> [Routes -> Keys \cup {None}]]
    /\ stored \in [Nodes -> SUBSET (Addr \X Write)]

Init ==
    /\ fixed = [n \in Nodes |-> [r \in Routes |-> None]]
    /\ stored = [n \in Nodes |-> {}]

(* The node's check of `w` at `a`, given the key fixed at `a` on that node. *)
AcceptLocked(a, w) ==
    /\ a[2] = w.route
    /\ CheckLock => a[3] = w.lock
    /\ w.grantSigner = w.lock
    /\ w.signer = w.granted

AcceptFirst(n, a, w) ==
    /\ a[2] = w.route
    /\ w.grantSigner = w.lock
    /\ w.granted = w.lock
    /\ w.signer = w.lock
    /\ CheckFixed => fixed[n][a[2]] \in {None, w.lock}

Accept(n, a, w) ==
    IF a \in LockedAddr THEN AcceptLocked(a, w) ELSE AcceptFirst(n, a, w)

(* A node takes a write: at a first inbox its first write fixes the key.   *)
Take(n, a, w) ==
    /\ Producible(w)
    /\ <<a, w>> \notin stored[n]
    /\ Accept(n, a, w)
    /\ stored' = [stored EXCEPT ![n] = @ \cup {<<a, w>>}]
    /\ fixed' = IF a \in FirstAddr /\ fixed[n][a[2]] = None
                  THEN [fixed EXCEPT ![n][a[2]] = w.lock]
                  ELSE fixed

(* Every write any node can still take is taken: the run is over. The model *)
(* is finite, so every behavior ends here.                                  *)
Settled ==
    /\ \A n \in Nodes, a \in Addr, w \in Write :
          ~(Producible(w) /\ <<a, w>> \notin stored[n] /\ Accept(n, a, w))
    /\ UNCHANGED vars

Next == (\E n \in Nodes, a \in Addr, w \in Write : Take(n, a, w)) \/ Settled

Spec == Init /\ [][Next]_vars

(* The grants the configs model: the honest lock "L" granted key "K"        *)
(* (a TLC configuration file cannot spell a tuple).                         *)
MCGranted == {<<"L", "K">>}

-----------------------------------------------------------------------------
(* Every write any node took at an honest lock's inbox is signed by a key  *)
(* that lock granted.                                                      *)
LockedHoldsOnlyGranted ==
    \A n \in Nodes : \A e \in stored[n] :
        (e[1] \in LockedAddr /\ e[1][3] \in HonestLocks) =>
            <<e[1][3], e[2].signer>> \in Granted

(* Every write a node holds at a first inbox is under the key fixed there.  *)
FirstInboxOneKey ==
    \A n \in Nodes : \A e \in stored[n] :
        e[1] \in FirstAddr => fixed[n][e[1][2]] = e[2].lock

(* At a lock-bound inbox every node decides every write the same, whatever *)
(* it holds.                                                               *)
NodesAgreeAtLocked ==
    \A n, m \in Nodes : \A a \in LockedAddr : \A w \in Write :
        Accept(n, a, w) = Accept(m, a, w)

(* A key fixed at a first inbox never moves.                               *)
FixedKeyNeverMoves ==
    [][\A n \in Nodes : \A r \in Routes :
         fixed[n][r] # None => fixed'[n][r] = fixed[n][r]]_vars

(* Non-vacuity: an honest grantee's write is taken at its lock's inbox, and *)
(* an attacker's write is taken at a first inbox before anyone else's.      *)
GrantedWriteReachable ==
    ~ \E n \in Nodes : \E e \in stored[n] :
        e[1] \in LockedAddr /\ e[1][3] \in HonestLocks
=============================================================================
