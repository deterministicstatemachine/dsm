---- MODULE DSM_BilateralLiveness ----
EXTENDS Integers, Sequences, FiniteSets, TLC

(***************************************************************************
  DSM Bilateral Liveness Specification
  =====================================

  No bilateral relationship reaches a state where its live devices cannot
  make progress. Each relationship is an independent two-party system with
  no global state, no coordinator and no consensus, so two devices are the
  whole model.

  The relationship carries two processes, one step at a time across both:
    - OFFLINE steps (bilateral sessions over a co-present link), abstracted
      to one commit on both devices; DSM_OfflineFinality.tla models the
      frames between the two commits and holds them to both-or-neither.
    - ONLINE transfers through storage, as the code runs them and as
      DSM.tla models them (the same rules and the same variable names):
        Send          T1: debit, the sender's lineage moves, the finality
                      gate is armed, the transfer is frozen in the outbox.
        RecvTransfer  T2+T3: the recipient applies a transfer whose debit was
                      admitted, whose signed parent is its pin of the
                      sender's head, and whose projection parent is its
                      current tip; it is credited, its journal
                      holds the countersign delta, and it awaits the
                      sender's certificate.
        RecvDelta     T4: the sender finalizes on the delta whose parent is
                      its pin of the recipient's head.
        CertPost      T5a: the certificate reaches quorum on storage, where
                      the recipient can read it; the gate stays.
        GateRelease   T5b: the sender's sweep finds it at quorum and releases
                      the gate.
        RecvCert      T6: the recipient reads it and is released.
      A send is never refunded and never rolled back. Two sends that cross
      both settle (owner ruling 2026-10-29, "both settle"): each device's
      projection is joined deterministically from the shared parent and the
      two children (Core `join_concurrent_tips`); each transfer keeps the
      parent it was signed against.

  Storage keeps what reaches it: a posted message is served, and may be read
  any number of times, until the sender's certificate collects it. A post can
  fail (a send's "delivery outcome unknown"); none is lost for good: the
  sender re-drives an unfinalized transfer and the recipient re-emits the
  delta its journal holds until the certificate exists. DSM.tla checks the
  same rules against a bag that also drops and repeats copies in flight.

  Properties (under the fairness below):
    1. SessionTermination: every offline step between devices that stay
       alive settles.
    2. OnlineSendSettles: every online send's gate is released, and every
       recipient awaiting a certificate is released, unless a device of the
       pair dies. Crossing sends included.
    3. RelationshipReturnsToRest: the relationship comes to rest — nothing
       in flight either way — infinitely often, so later online and offline
       steps can be made.
    4. NoDeadlock (TLC CHECK_DEADLOCK).

  Safety invariants:
    - TypeOK
    - NoFork: no signer consumes its own lineage parent twice
    - TokenConservation: balances + admitted debits in flight + burned value
      is constant
    - ProjectionAgreement: at rest, both devices hold one tip and pin each
      other's lineage head
    - BarrierHeldDurably: a gate is held by its frozen send, an awaited
      certificate by its journal
    - BalancesNonNegative

  Falsification (registered config):
    - DSM_BilateralLiveness_CrossingNotJoined.cfg: JoinCrossingSteps = FALSE
      — the projection sync refuses a crossing step (the code before the
      ruling); two crossing sends wedge and OnlineSendSettles fails.

  Out of this model, recorded as boundaries:
    - Vaults: the DLV manager and LimboVault serve only the dBTC tap (out of
      this round), and beta has no vault expiry (DSM Amendment A23, B5).
      SoFi vaults are modeled in DSM_SofiFulfillment / DSM_SofiSuccessorCells.
    - Recovery (capsule, tombstone, succession) is out of this round.
    - Restart: every durable row survives it and nothing is held in memory
      across it, so a restart is not an event of this model.

  Code traceability:
    - Send: handlers/app_router_impl.rs (wallet.send), online_outbox.rs
      (`pending_online_outbox`, `local_bilateral_chain_tip`)
    - RecvTransfer: handlers/storage_routes.rs (the recipient apply; the
      projection parent from the signed nonce), recipient_receipt.rs (the
      fold's tip sync), counterparty_canonical_heads.rs (the pin)
    - RecvDelta: sender_outbox.rs (acceptance finalization: projection sync,
      pin CAS, proposal finalized; the gate stays)
    - CertPost, GateRelease: the certificate's delivery and the checkpoint
      sweep (the only deleter of the gate)
    - RecvCert: handlers/relationship_finalized.rs
    - TipSync: storage/client_db/bilateral_tip_sync.rs
      (`sync_tip_projections_in_tx`, crossing steps joined)
    - Offline steps: bluetooth/bilateral_ble_handler.rs
***************************************************************************)

\* ========================================================================
\* CONSTANTS
\* ========================================================================

CONSTANTS
    Device,             \* the two devices of the relationship, e.g. {d1, d2}
    SessionId,          \* offline session identifiers, e.g. {s1}
    INITIAL_BALANCE,    \* starting balance per device
    StepsPerDevice,     \* how many steps (online sends and offline proposals) each device begins
    NULL,               \* sentinel value
    JoinCrossingSteps   \* TRUE as the code runs: the projection sync joins a crossing step

\* Derived constants
Phase == {"Preparing", "Prepared", "PendingUserAction",
          "Accepted", "Rejected", "Committed", "Failed"}

TerminalPhase == {"Rejected", "Committed", "Failed"}

InFlightPhase == {"Preparing", "Prepared", "PendingUserAction", "Accepted"}

Pairs == { <<d, p>> \in Device \X Device : d # p }

\* The relationship's genesis seed: both projections and both lineages start
\* there, and each device pins the other's head there.
GENESIS == 1

\* ERA destroyed to create one token (dsm::core::token::TOKEN_CREATION_FEE_ERA).
TOKEN_CREATION_FEE == 10

MinNat(S) == CHOOSE x \in S : \A y \in S : x <= y
MaxNat(S) == CHOOSE x \in S : \A y \in S : x >= y

\* ========================================================================
\* VARIABLES
\* ========================================================================

VARIABLES
    deviceBalance,   \* deviceBalance[d] \in Nat
    deviceAlive,     \* deviceAlive[d] \in BOOLEAN
    begun,           \* begun[d]: steps d has begun (bounds the model)
    sessions,        \* sessions[sid] = offline session record or NULL
    coPresent,       \* BOOLEAN: BLE proximity
    networkUp,       \* networkUp[d] \in BOOLEAN
    tip,             \* tip[<<d,p>>]: d's projection tip (contacts.chain_tip)
    online,          \* online[<<d,p>>]: prev/local tips, lineage head, pin, gate, awaited certificate
    outbox,          \* senders' frozen sends not yet released: the admitted debits
    journal,         \* recipients' countersign deltas awaiting the certificate
    certs,           \* step ids whose certificate reached quorum
    joins,           \* the join oracle: [parent, lo, hi] -> tip
    net,             \* messages on storage: served until collected; reading one does not remove it
    nextMsgId,       \* fresh value allocator (clockless)
    ledger,          \* accepted lineage steps: [signer, oldTip, newTip]
    burnedTotal      \* ERA destroyed by token creation

vars == <<deviceBalance, deviceAlive, begun, sessions, coPresent, networkUp,
          tip, online, outbox, journal, certs, joins, net, nextMsgId, ledger, burnedTotal>>

onlineVars == <<tip, online, outbox, journal, certs, joins, net, nextMsgId, ledger>>

\* ========================================================================
\* INITIAL STATE
\* ========================================================================

Init ==
    /\ deviceBalance = [d \in Device |-> INITIAL_BALANCE]
    /\ deviceAlive = [d \in Device |-> TRUE]
    /\ begun = [d \in Device |-> 0]
    /\ sessions = [sid \in SessionId |-> NULL]
    /\ coPresent = TRUE
    /\ networkUp = [d \in Device |-> TRUE]
    /\ tip = [x \in Pairs |-> GENESIS]
    /\ online = [x \in Pairs |-> [prev |-> 0, local |-> GENESIS, lin |-> GENESIS, pin |-> GENESIS,
                                  gate |-> 0, awaits |-> 0]]
    /\ outbox = {}
    /\ journal = {}
    /\ certs = {}
    /\ joins = {}
    /\ net = {}
    /\ nextMsgId = GENESIS + 1
    /\ ledger = {}
    /\ burnedTotal = 0

\* ========================================================================
\* SHARED DEFINITIONS (as in DSM.tla)
\* ========================================================================

View(d, p) == [chain |-> tip[<<d, p>>], prev |-> online[<<d, p>>].prev, local |-> online[<<d, p>>].local]

JoinEntry(parent, a, b) ==
    { j \in joins : j.parent = parent /\ j.lo = MinNat({a, b}) /\ j.hi = MaxNat({a, b}) }

JoinTip(parent, a, b, fresh) ==
    IF JoinEntry(parent, a, b) # {} THEN (CHOOSE j \in JoinEntry(parent, a, b) : TRUE).tip
    ELSE fresh

JoinsAfter(parent, a, b, fresh) ==
    IF JoinEntry(parent, a, b) # {} THEN joins
    ELSE joins \union {[parent |-> parent, lo |-> MinNat({a, b}), hi |-> MaxNat({a, b}), tip |-> fresh]}

\* `sync_tip_projections_in_tx`, case for case; the join case only when the
\* code joins crossing steps.
TipSync(v, parent, target, fresh) ==
    IF v.chain = target
    THEN [ok |-> TRUE, chain |-> target, prev |-> v.prev, local |-> target]
    ELSE IF v.chain = parent
    THEN [ok |-> TRUE, chain |-> target, prev |-> parent, local |-> target]
    ELSE IF JoinCrossingSteps /\ v.prev = parent /\ v.local = v.chain
    THEN [ok |-> TRUE, chain |-> JoinTip(parent, v.chain, target, fresh), prev |-> v.chain,
          local |-> JoinTip(parent, v.chain, target, fresh)]
    ELSE IF /\ JoinCrossingSteps
            /\ v.prev # 0 /\ v.prev # parent /\ v.prev # target
            /\ JoinEntry(parent, v.prev, target) # {}
            /\ JoinTip(parent, v.prev, target, fresh) = v.chain
            /\ v.local = v.chain
    THEN [ok |-> TRUE, chain |-> v.chain, prev |-> v.prev, local |-> v.local]
    ELSE [ok |-> FALSE, chain |-> v.chain, prev |-> v.prev, local |-> v.local]

JoinsAfterSync(v, parent, target, fresh) ==
    IF JoinCrossingSteps /\ v.chain # target /\ v.chain # parent /\ v.prev = parent /\ v.local = v.chain
    THEN JoinsAfter(parent, v.chain, target, fresh)
    ELSE joins

Applied(t) == [signer |-> t.from, oldTip |-> t.sp, newTip |-> t.sc] \in ledger

Settled(d, p) ==
    /\ online[<<d, p>>].gate = 0
    /\ online[<<d, p>>].awaits = 0
    /\ ~\E r \in outbox : r.from = d /\ r.to = p

AtRest == \A x \in Pairs : Settled(x[1], x[2])

NoOfflineStepInFlight ==
    ~\E sid \in SessionId : sessions[sid] /= NULL /\ sessions[sid].phase \in InFlightPhase

TransferMsg(r) ==
    [id |-> r.id, kind |-> "transfer", from |-> r.from, to |-> r.to, payload |-> r.payload,
     sp |-> r.sp, sc |-> r.sc, pp |-> r.pp, pc |-> r.pc]

DeltaMsg(j) ==
    [id |-> j.id, kind |-> "delta", from |-> j.from, to |-> j.to, payload |-> 0,
     sp |-> j.sp, sc |-> j.sc, pp |-> j.pp, pc |-> j.pc]

\* ========================================================================
\* ONLINE TRANSFERS
\* ========================================================================

\* T1. The finality barrier: no send while the sender's own send is in flight,
\* while it awaits the peer's certificate, or while an offline step is in
\* flight on the relationship.
Send(d, p, amt, posted) ==
    LET id == nextMsgId
        o  == online[<<d, p>>]
        r  == [id |-> id, from |-> d, to |-> p, payload |-> amt,
               sp |-> o.lin, sc |-> id, pp |-> tip[<<d, p>>], pc |-> id, fin |-> FALSE]
    IN
    /\ d # p
    /\ deviceAlive[d]
    /\ networkUp[d]
    /\ begun[d] < StepsPerDevice
    /\ NoOfflineStepInFlight
    /\ o.gate = 0
    /\ o.awaits = 0
    /\ o.local = tip[<<d, p>>]
    /\ amt > 0
    /\ deviceBalance[d] >= amt
    /\ outbox' = outbox \union {r}
    /\ net' = IF posted THEN net \union {TransferMsg(r)} ELSE net
    /\ online' = [online EXCEPT ![<<d, p>>].lin = id, ![<<d, p>>].local = id, ![<<d, p>>].gate = id]
    /\ deviceBalance' = [deviceBalance EXCEPT ![d] = @ - amt]
    /\ begun' = [begun EXCEPT ![d] = @ + 1]
    /\ nextMsgId' = nextMsgId + 1
    /\ UNCHANGED <<deviceAlive, sessions, coPresent, networkUp, tip, journal, certs, joins, ledger, burnedTotal>>

\* T2+T3. The recipient applies the transfer `m`. Reading a message does not
\* take it off storage: it can be read again.
RecvTransfer(m, posted) ==
    LET d     == m.to
        p     == m.from
        o     == online[<<d, p>>]
        v     == View(d, p)
        bc    == nextMsgId
        fresh == nextMsgId + 1
        s     == TipSync(v, m.pp, m.pc, fresh)
        j     == [id |-> m.id, from |-> d, to |-> p, sp |-> o.lin, sc |-> bc, pp |-> m.pp, pc |-> m.pc]
    IN
    /\ m \in net
    /\ m.kind = "transfer"
    /\ deviceAlive[d]
    /\ networkUp[d]
    /\ ~Applied(m)
    /\ \E r \in outbox : r.id = m.id /\ r.from = p /\ r.to = d /\ r.sp = m.sp /\ r.sc = m.sc
    /\ o.awaits = 0
    /\ m.sp = o.pin
    /\ m.pp = v.chain
    /\ s.ok
    /\ tip' = [tip EXCEPT ![<<d, p>>] = s.chain]
    /\ online' = [online EXCEPT ![<<d, p>>] =
                    [o EXCEPT !.prev = s.prev, !.local = s.local, !.lin = bc, !.pin = m.sc, !.awaits = m.id]]
    /\ deviceBalance' = [deviceBalance EXCEPT ![d] = @ + m.payload]
    /\ ledger' = ledger \union {[signer |-> p, oldTip |-> m.sp, newTip |-> m.sc]}
    /\ journal' = journal \union {j}
    /\ joins' = JoinsAfterSync(v, m.pp, m.pc, fresh)
    /\ net' = IF posted THEN net \union {DeltaMsg(j)} ELSE net
    /\ nextMsgId' = nextMsgId + 2
    /\ UNCHANGED <<deviceAlive, begun, sessions, coPresent, networkUp, outbox, certs, burnedTotal>>

\* T4. The sender finalizes its send on the delta `m`.
RecvDelta(m) ==
    LET d     == m.to
        p     == m.from
        o     == online[<<d, p>>]
        v     == View(d, p)
        fresh == nextMsgId
        r     == CHOOSE x \in outbox : x.id = m.id
        s     == TipSync(v, r.pp, r.pc, fresh)
    IN
    /\ m \in net
    /\ m.kind = "delta"
    /\ deviceAlive[d]
    /\ networkUp[d]
    /\ \E x \in outbox : x.id = m.id /\ x.from = d /\ x.to = p /\ ~x.fin
    /\ o.gate = m.id
    /\ m.sp = o.pin
    /\ s.ok
    /\ tip' = [tip EXCEPT ![<<d, p>>] = s.chain]
    /\ online' = [online EXCEPT ![<<d, p>>] = [o EXCEPT !.prev = s.prev, !.local = s.local, !.pin = m.sc]]
    /\ outbox' = (outbox \ {r}) \union {[r EXCEPT !.fin = TRUE]}
    /\ ledger' = ledger \union {[signer |-> p, oldTip |-> m.sp, newTip |-> m.sc]}
    /\ joins' = JoinsAfterSync(v, r.pp, r.pc, fresh)
    /\ nextMsgId' = nextMsgId + 1
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, sessions, coPresent, networkUp, journal, certs, net, burnedTotal>>

\* T5a. The finalized send's certificate reaches quorum on storage, where the
\* recipient can read it. The gate stays until the sender's sweep sees it.
CertPost(d, p) ==
    /\ d # p
    /\ LET s == online[<<d, p>>].gate
       IN /\ s # 0
          /\ s \notin certs
          /\ deviceAlive[d]
          /\ networkUp[d]
          /\ \E r \in outbox : r.id = s /\ r.fin
          /\ certs' = certs \union {s}
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, sessions, coPresent, networkUp, tip, online, outbox, journal, joins, net, nextMsgId, ledger, burnedTotal>>

\* T5b. The sender's sweep finds its certificate at quorum and releases the
\* gate. Storage no longer serves the send's transfer or its delta.
GateRelease(d, p) ==
    /\ d # p
    /\ LET s == online[<<d, p>>].gate
       IN /\ s # 0
          /\ s \in certs
          /\ deviceAlive[d]
          /\ networkUp[d]
          /\ outbox' = { r \in outbox : r.id # s }
          /\ online' = [online EXCEPT ![<<d, p>>].gate = 0]
          /\ net' = { m \in net : m.id # s }
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, sessions, coPresent, networkUp, tip, journal, certs, joins, nextMsgId, ledger, burnedTotal>>

\* T6. The recipient reads the certificate and is released.
RecvCert(d, p) ==
    /\ d # p
    /\ LET s == online[<<d, p>>].awaits
       IN /\ s # 0
          /\ s \in certs
          /\ deviceAlive[d]
          /\ networkUp[d]
          /\ journal' = { j \in journal : j.id # s }
          /\ online' = [online EXCEPT ![<<d, p>>].awaits = 0]
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, sessions, coPresent, networkUp, tip, outbox, certs, joins, net, nextMsgId, ledger, burnedTotal>>

\* The sender re-drives a transfer it has not finalized.
RedriveTransfer(r) ==
    /\ r \in outbox
    /\ ~r.fin
    /\ deviceAlive[r.from]
    /\ networkUp[r.from]
    /\ TransferMsg(r) \notin net
    /\ net' = net \union {TransferMsg(r)}
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, sessions, coPresent, networkUp, tip, online, outbox, journal, certs, joins, nextMsgId, ledger, burnedTotal>>

\* The recipient re-emits the delta its journal holds until the certificate
\* exists (from then on it reads the certificate instead).
RedriveDelta(j) ==
    /\ j \in journal
    /\ j.id \notin certs
    /\ deviceAlive[j.from]
    /\ networkUp[j.from]
    /\ DeltaMsg(j) \notin net
    /\ net' = net \union {DeltaMsg(j)}
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, sessions, coPresent, networkUp, tip, online, outbox, journal, certs, joins, nextMsgId, ledger, burnedTotal>>

\* ========================================================================
\* OFFLINE STEPS
\* ========================================================================

\* ---------- SenderPrepare ----------
\* One step at a time on the relationship, across both processes: no offline
\* step in flight, and nothing online in flight either way.
SenderPrepare(sender, receiver, sid, amount) ==
    /\ sender /= receiver
    /\ deviceAlive[sender]
    /\ deviceAlive[receiver]
    /\ begun[sender] < StepsPerDevice
    /\ sessions[sid] = NULL
    /\ deviceBalance[sender] >= amount
    /\ amount > 0
    /\ NoOfflineStepInFlight
    /\ AtRest
    /\ sessions' = [sessions EXCEPT ![sid] =
        [phase |-> "Prepared",
         sender |-> sender,
         receiver |-> receiver,
         tipAtCreation |-> online[<<sender, receiver>>].lin,
         amount |-> amount,
         hasBothSigs |-> FALSE]]
    /\ begun' = [begun EXCEPT ![sender] = @ + 1]
    /\ UNCHANGED <<deviceBalance, deviceAlive, coPresent, networkUp, burnedTotal>>
    /\ UNCHANGED onlineVars

\* ---------- ReceiverReceivePrepare ----------
ReceiverReceivePrepare(sid) ==
    /\ sessions[sid] /= NULL
    /\ sessions[sid].phase = "Prepared"
    /\ deviceAlive[sessions[sid].receiver]
    /\ coPresent
    /\ sessions' = [sessions EXCEPT ![sid].phase = "PendingUserAction"]
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, coPresent, networkUp, burnedTotal>>
    /\ UNCHANGED onlineVars

\* ---------- UserAccept ----------
UserAccept(sid) ==
    /\ sessions[sid] /= NULL
    /\ sessions[sid].phase = "PendingUserAction"
    /\ deviceAlive[sessions[sid].receiver]
    /\ sessions' = [sessions EXCEPT ![sid].phase = "Accepted",
                                     ![sid].hasBothSigs = TRUE]
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, coPresent, networkUp, burnedTotal>>
    /\ UNCHANGED onlineVars

\* ---------- UserReject ----------
UserReject(sid) ==
    /\ sessions[sid] /= NULL
    /\ sessions[sid].phase = "PendingUserAction"
    /\ sessions' = [sessions EXCEPT ![sid].phase = "Rejected"]
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, coPresent, networkUp, burnedTotal>>
    /\ UNCHANGED onlineVars

\* ---------- Commit ----------
\* Tripwire: the sender's lineage head is still the one the step was prepared
\* on. Both lineages advance, each device pins the other's new head, both
\* projections advance and the amount moves.
Commit(sid) ==
    LET s   == sessions[sid].sender
        r   == sessions[sid].receiver
        amt == sessions[sid].amount
        t   == tip[<<s, r>>]
        c1  == nextMsgId
        c2  == nextMsgId + 1
        os  == online[<<s, r>>]
        orr == online[<<r, s>>]
    IN
    /\ sessions[sid] /= NULL
    /\ sessions[sid].phase = "Accepted"
    /\ sessions[sid].hasBothSigs = TRUE
    /\ os.lin = sessions[sid].tipAtCreation
    /\ deviceAlive[s]
    /\ deviceAlive[r]
    /\ sessions' = [sessions EXCEPT ![sid].phase = "Committed"]
    /\ deviceBalance' = [deviceBalance EXCEPT ![s] = @ - amt, ![r] = @ + amt]
    /\ tip' = [tip EXCEPT ![<<s, r>>] = c1, ![<<r, s>>] = c1]
    /\ online' = [online EXCEPT
         ![<<s, r>>] = [os EXCEPT !.prev = t, !.local = c1, !.lin = c1, !.pin = c2],
         ![<<r, s>>] = [orr EXCEPT !.prev = t, !.local = c1, !.lin = c2, !.pin = c1]]
    /\ ledger' = ledger \union {[signer |-> s, oldTip |-> os.lin, newTip |-> c1],
                                [signer |-> r, oldTip |-> orr.lin, newTip |-> c2]}
    /\ nextMsgId' = nextMsgId + 2
    /\ UNCHANGED <<deviceAlive, begun, coPresent, networkUp, outbox, journal, certs, joins, net, burnedTotal>>

\* ---------- ProposerCancel ----------
\* The proposer ends a proposal it has not confirmed, with a signed
\* cancellation. Past its confirm nothing ends the step but its commit.
ProposerCancel(sid) ==
    /\ sessions[sid] /= NULL
    /\ sessions[sid].phase \in {"Preparing", "Prepared"}
    /\ deviceAlive[sessions[sid].sender]
    /\ sessions' = [sessions EXCEPT ![sid].phase = "Rejected"]
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, coPresent, networkUp, burnedTotal>>
    /\ UNCHANGED onlineVars

\* ---------- TripwireAbort ----------
\* The sender's lineage moved since the precommitment: the step fails.
TripwireAbort(sid) ==
    /\ sessions[sid] /= NULL
    /\ sessions[sid].phase = "Accepted"
    /\ online[<<sessions[sid].sender, sessions[sid].receiver>>].lin /= sessions[sid].tipAtCreation
    /\ sessions' = [sessions EXCEPT ![sid].phase = "Failed"]
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, coPresent, networkUp, burnedTotal>>
    /\ UNCHANGED onlineVars

\* ========================================================================
\* ENVIRONMENT
\* ========================================================================

PartitionStart(d) ==
    /\ networkUp[d]
    /\ networkUp' = [networkUp EXCEPT ![d] = FALSE]
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, sessions, coPresent, burnedTotal>>
    /\ UNCHANGED onlineVars

PartitionEnd(d) ==
    /\ ~networkUp[d]
    /\ networkUp' = [networkUp EXCEPT ![d] = TRUE]
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, sessions, coPresent, burnedTotal>>
    /\ UNCHANGED onlineVars

BleConnect ==
    /\ ~coPresent
    /\ coPresent' = TRUE
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, sessions, networkUp, burnedTotal>>
    /\ UNCHANGED onlineVars

BleDisconnect ==
    /\ coPresent
    /\ coPresent' = FALSE
    /\ UNCHANGED <<deviceBalance, deviceAlive, begun, sessions, networkUp, burnedTotal>>
    /\ UNCHANGED onlineVars

\* Device failure. A step in flight with the failed device fails nothing on its
\* peer: the peer cannot tell a dead device from an absent one. It stays in
\* flight (the liveness properties except it).
DeviceFail(d) ==
    /\ deviceAlive[d]
    /\ deviceAlive' = [deviceAlive EXCEPT ![d] = FALSE]
    /\ UNCHANGED <<deviceBalance, begun, sessions, coPresent, networkUp, burnedTotal>>
    /\ UNCHANGED onlineVars

\* ========================================================================
\* TOKEN CREATION
\* ========================================================================

\* Create a token: DESTROY the fee from the creator's ERA balance. The
\* issuance leg credits a different asset this single-asset model does not
\* track, so the fee must land in `burnedTotal` for conservation to close.
\* Insufficient balance changes nothing.
CreateTokenBurn(d) ==
    /\ deviceAlive[d]
    /\ deviceBalance[d] >= TOKEN_CREATION_FEE
    /\ deviceBalance' = [deviceBalance EXCEPT ![d] = @ - TOKEN_CREATION_FEE]
    /\ burnedTotal' = burnedTotal + TOKEN_CREATION_FEE
    /\ UNCHANGED <<deviceAlive, begun, sessions, coPresent, networkUp>>
    /\ UNCHANGED onlineVars

\* ========================================================================
\* NEXT-STATE RELATION
\* ========================================================================

\* Delivery to `d` of some transfer, or of some delta, on storage.
DeliverTransferTo(d) == \E m \in net, posted \in BOOLEAN : m.to = d /\ RecvTransfer(m, posted)
DeliverDeltaTo(d) == \E m \in net : m.to = d /\ RecvDelta(m)

Next ==
    \/ \E d \in Device : CreateTokenBurn(d)
    \* Offline steps
    \/ \E s, r \in Device, sid \in SessionId, amt \in 1..INITIAL_BALANCE :
        SenderPrepare(s, r, sid, amt)
    \/ \E sid \in SessionId : ReceiverReceivePrepare(sid)
    \/ \E sid \in SessionId : UserAccept(sid)
    \/ \E sid \in SessionId : UserReject(sid)
    \/ \E sid \in SessionId : Commit(sid)
    \/ \E sid \in SessionId : ProposerCancel(sid)
    \/ \E sid \in SessionId : TripwireAbort(sid)
    \* Online transfers
    \/ \E d, p \in Device, amt \in 1..INITIAL_BALANCE, posted \in BOOLEAN : Send(d, p, amt, posted)
    \/ \E d \in Device : DeliverTransferTo(d)
    \/ \E d \in Device : DeliverDeltaTo(d)
    \/ \E d, p \in Device : CertPost(d, p)
    \/ \E d, p \in Device : GateRelease(d, p)
    \/ \E d, p \in Device : RecvCert(d, p)
    \/ \E r \in outbox : RedriveTransfer(r)
    \/ \E j \in journal : RedriveDelta(j)
    \* Environment
    \/ \E d \in Device : PartitionStart(d)
    \/ \E d \in Device : PartitionEnd(d)
    \/ BleConnect
    \/ BleDisconnect
    \/ \E d \in Device : DeviceFail(d)

\* ========================================================================
\* SAFETY INVARIANTS
\* ========================================================================

TypeOK ==
    /\ deviceBalance \in [Device -> Nat]
    /\ deviceAlive \in [Device -> BOOLEAN]
    /\ begun \in [Device -> 0..StepsPerDevice]
    /\ \A sid \in SessionId :
        sessions[sid] = NULL \/
        (/\ sessions[sid].phase \in Phase
         /\ sessions[sid].sender \in Device
         /\ sessions[sid].receiver \in Device
         /\ sessions[sid].tipAtCreation \in Nat
         /\ sessions[sid].amount \in 1..INITIAL_BALANCE
         /\ sessions[sid].hasBothSigs \in BOOLEAN)
    /\ coPresent \in BOOLEAN
    /\ networkUp \in [Device -> BOOLEAN]
    /\ tip \in [Pairs -> Nat]
    /\ online \in [Pairs -> [prev: Nat, local: Nat, lin: Nat, pin: Nat, gate: Nat, awaits: Nat]]
    /\ outbox \subseteq [id: Nat, from: Device, to: Device, payload: 1..INITIAL_BALANCE,
                         sp: Nat, sc: Nat, pp: Nat, pc: Nat, fin: BOOLEAN]
    /\ journal \subseteq [id: Nat, from: Device, to: Device, sp: Nat, sc: Nat, pp: Nat, pc: Nat]
    /\ certs \subseteq Nat
    /\ joins \subseteq [parent: Nat, lo: Nat, hi: Nat, tip: Nat]
    /\ net \subseteq [id: Nat, kind: {"transfer", "delta"}, from: Device, to: Device,
                      payload: 0..INITIAL_BALANCE, sp: Nat, sc: Nat, pp: Nat, pc: Nat]
    /\ nextMsgId \in Nat
    /\ ledger \subseteq [signer: Device, oldTip: Nat, newTip: Nat]
    /\ burnedTotal \in Nat

\* NoFork (Tripwire): no signer consumes its own lineage parent twice.
NoFork ==
    \A l1, l2 \in ledger :
        (l1.signer = l2.signer /\ l1.oldTip = l2.oldTip) => l1.newTip = l2.newTip

RECURSIVE SumBal(_)
SumBal(S) == IF S = {} THEN 0
             ELSE LET d == CHOOSE x \in S : TRUE
                  IN deviceBalance[d] + SumBal(S \ {d})

RECURSIVE SumPayload(_)
SumPayload(S) == IF S = {} THEN 0
                 ELSE LET r == CHOOSE x \in S : TRUE IN r.payload + SumPayload(S \ {r})

\* TokenConservation: ERA is conserved modulo the tracked burn. An admitted
\* debit not yet credited is value in flight, never lost.
TokenConservation ==
    SumBal(Device) + SumPayload({ r \in outbox : ~Applied(r) }) + burnedTotal
        = Cardinality(Device) * INITIAL_BALANCE

\* At rest, both devices hold one tip and each pins the other's lineage head.
ProjectionAgreement ==
    AtRest =>
        \A x \in Pairs :
            /\ tip[x] = tip[<<x[2], x[1]>>]
            /\ online[x].pin = online[<<x[2], x[1]>>].lin

\* The barrier is held by durable state.
BarrierHeldDurably ==
    \A x \in Pairs :
        /\ online[x].gate # 0 => \E r \in outbox : r.id = online[x].gate /\ r.from = x[1] /\ r.to = x[2]
        /\ online[x].awaits # 0 => \E j \in journal : j.id = online[x].awaits /\ j.from = x[1] /\ j.to = x[2]

BalancesNonNegative ==
    \A d \in Device : deviceBalance[d] >= 0

\* ========================================================================
\* LIVENESS
\* ========================================================================

\* Weak fairness on what a live device eventually does by itself (answer its
\* user, commit, abort on a tripwire, release a gate at quorum, read a
\* certificate, re-drive), on partitions and the link healing; strong
\* fairness on delivery, which drops and partitions can interrupt.
Fairness ==
    /\ \A sid \in SessionId :
        /\ WF_vars(UserAccept(sid))
        /\ WF_vars(UserReject(sid))
        /\ WF_vars(Commit(sid))
        /\ WF_vars(TripwireAbort(sid))
        /\ SF_vars(ReceiverReceivePrepare(sid))
    /\ \A d \in Device :
        /\ SF_vars(DeliverTransferTo(d))
        /\ SF_vars(DeliverDeltaTo(d))
        /\ WF_vars(PartitionEnd(d))
    \* Over the relationship's two directions: with d = p these actions are
    \* never enabled, and a fairness condition on them would only cost TLC.
    /\ \A x \in Pairs :
        /\ SF_vars(CertPost(x[1], x[2]))
        /\ SF_vars(GateRelease(x[1], x[2]))
        /\ SF_vars(RecvCert(x[1], x[2]))
    /\ SF_vars(\E r \in outbox : RedriveTransfer(r))
    /\ SF_vars(\E j \in journal : RedriveDelta(j))
    /\ WF_vars(BleConnect)

Spec == Init /\ [][Next]_vars /\ Fairness

BothAlive == \A d \in Device : deviceAlive[d]

\* 1. Every offline step between devices that stay alive settles.
SessionTermination ==
    \A sid \in SessionId :
        [](sessions[sid] /= NULL /\ sessions[sid].phase \in InFlightPhase
           => <>(\/ sessions[sid] = NULL
                 \/ sessions[sid].phase \in TerminalPhase
                 \/ ~deviceAlive[sessions[sid].sender]
                 \/ ~deviceAlive[sessions[sid].receiver]))

\* 2. Every online send's gate releases and every awaited certificate
\*    arrives, crossing sends included, unless a device of the pair dies.
OnlineSendSettles ==
    \A x \in Pairs :
        /\ [](online[x].gate # 0 => <>(online[x].gate = 0 \/ ~BothAlive))
        /\ [](online[x].awaits # 0 => <>(online[x].awaits = 0 \/ ~BothAlive))

\* 3. The relationship comes to rest infinitely often: it never wedges.
RelationshipReturnsToRest ==
    []<>(AtRest \/ ~BothAlive)

\* Non-vacuity witnesses (each expected violated in its registered config).
NeverCrossed ==
    ~\E x \in Pairs : online[x].gate # 0 /\ online[<<x[2], x[1]>>].gate # 0
                      /\ \E r1, r2 \in outbox : r1.from = x[1] /\ r2.from = x[2] /\ r1.pp = r2.pp

NeverSettledCrossing ==
    ~(AtRest /\ joins # {} /\ \A x \in Pairs : tip[x] \in { j.tip : j \in joins })

Safety ==
    /\ TypeOK
    /\ NoFork
    /\ TokenConservation
    /\ ProjectionAgreement
    /\ BarrierHeldDurably
    /\ BalancesNonNegative

====
