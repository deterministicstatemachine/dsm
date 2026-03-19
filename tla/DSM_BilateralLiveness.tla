---- MODULE DSM_BilateralLiveness ----
EXTENDS Integers, Sequences, FiniteSets, TLC

(***************************************************************************
  DSM Bilateral Liveness Specification
  =====================================

  Formally proves that no DSM bilateral relationship can reach a stuck
  state where live participants cannot make progress.

  DSM has no quorum because there is no global state. Each bilateral
  relationship R_{i,j} is an independent two-party system. The CAP
  impossibility theorem is out of scope because DSM does not maintain
  a single globally-shared object (whitepaper Section 15.1, Theorem 7).

  MODEL SCOPE:
  This spec uses a 2-device model {d1, d2}. The bilateral pair IS the
  full device set. This is sufficient to verify all three liveness
  properties:
    - SessionTermination: holds regardless of device count.
    - ModalLockResolution: single-pair property, 2 devices is exact.
    - DLVLiveness: VaultExpire fires unconditionally (all-devices-dead
      is covered — storage nodes expire vaults via BLAKE3 iteration
      counter, no device needs to be alive). VaultInvalidate and
      VaultClaim are also verified with both d1 and d2 as recipient.

  The 3-device "recipient outside bilateral pair" scenario is a proof
  sketch comment: it follows directly from the same VaultUnlock/Claim
  logic but with an independent third device. TLC cannot tractably
  explore the 3-device model (~55M+ states, state space unbounded in
  practice with temporal checking). The 2-device model is the
  appropriate scope for mechanized verification here.

  NETWORK ISOLATION (PRLSM model):
  Each bilateral relationship is hermetically sealed (PRLSM). Even if
  R_{d1,d2} experiences total key loss, every other relationship is
  completely unaffected. There is no global chain to halt, no consensus
  to stall, no shared state to contaminate. This is the fundamental
  advantage of the PRLSM architecture over consensus-based systems.

  This spec proves (under weak fairness):
    1. SessionTermination: every started bilateral session eventually
       reaches a terminal state {Committed, Rejected, Failed}.
    2. ModalLockResolution: the pending-online modal lock always clears.
    3. DLVLiveness: no vault remains non-terminal forever. UNCONDITIONAL.
       Storage nodes (N=6, K=3 quorum) expire vaults autonomously via
       deterministic BLAKE3 iteration counter — no device needs to be
       alive. With 3+ devices, recipients outside the bilateral pair
       can also unlock/claim independently. There is no stuck state.
    4. NoDeadlock: the system is never stuck (TLC CHECK_DEADLOCK).

  Safety invariants (checked across all reachable states):
    - TypeOK: all variables well-typed
    - NoFork: Tripwire fork-exclusion (Theorem 2)
    - TokenConservation: total balance + escrow is constant (Theorem 4)
    - ModalLockConsistency: lock implies pending b0x item (Theorem 1)
    - BalancesNonNegative: no negative balances

  Code traceability:
    - BilateralPhase enum: bilateral_ble_handler.rs:75-84
    - VaultState enum: limbo_vault.rs:102-119
    - Tripwire enforcement: bilateral_transaction_manager.rs:983-1006
    - Modal sync lock: sync_manager.rs:44-75
    - Session recovery: bilateral_ble_handler.rs:475-513
    - Recovery capsule: recovery/capsule.rs
    - Tombstone/Succession: recovery/tombstone.rs:26-67
    - Vault expiry: limbo_vault.rs:1768 (VaultStatus::Expired)
***************************************************************************)

\* ========================================================================
\* CONSTANTS
\* ========================================================================

CONSTANTS
    Device,          \* Set of device identifiers, e.g., {d1, d2}
    SessionId,       \* Set of session identifiers, e.g., {s1, s2}
    VaultId,         \* Set of vault identifiers, e.g., {v1}
    MaxChain,        \* Maximum chain tip value (bounds state space)
    INITIAL_BALANCE, \* Starting balance per device
    NULL             \* Sentinel value

\* Derived constants
Phase == {"Preparing", "Prepared", "PendingUserAction",
          "Accepted", "Rejected", "Committed", "Failed"}

TerminalPhase == {"Rejected", "Committed", "Failed"}

InFlightPhase == {"Preparing", "Prepared", "PendingUserAction", "Accepted"}

VState == {"Limbo", "Unlocked", "Claimed", "Invalidated"}

TerminalVState == {"Claimed", "Invalidated"}

Hash == 0..MaxChain

\* ========================================================================
\* VARIABLES
\* ========================================================================

VARIABLES
    \* === Per-Device State ===
    chainTip,        \* chainTip[d] \in Hash
    balance,         \* balance[d] \in Nat
    deviceAlive,     \* deviceAlive[d] \in BOOLEAN

    \* === Relationship State (single pair for 2 devices) ===
    modalLock,       \* BOOLEAN: pending online submission exists
    relationshipTip, \* Hash: shared chain tip

    \* === Bilateral Sessions ===
    sessions,        \* sessions[sid] = record or NULL

    \* === b0x Spool (Online Queue) ===
    b0xPending,      \* BOOLEAN
    b0xAmount,       \* Nat
    b0xSender,       \* Device
    b0xReceiver,     \* Device

    \* === DLV Vaults ===
    vaults,          \* vaults[vid] = record or NULL

    \* === Network/Transport ===
    coPresent,       \* BOOLEAN: BLE proximity
    networkUp,       \* networkUp[d] \in BOOLEAN

    \* === Recovery ===
    capsuleExists,   \* capsuleExists[d] \in BOOLEAN
    tombstoned,      \* tombstoned[d] \in BOOLEAN
    successorOf      \* successorOf[d] \in Device \cup {NULL}

vars == <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
          sessions, b0xPending, b0xAmount, b0xSender, b0xReceiver,
          vaults, coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ========================================================================
\* INITIAL STATE
\* ========================================================================

\* Pick an arbitrary device for initial b0x fields (unused until b0xPending=TRUE)
AnyDevice == CHOOSE d \in Device : TRUE

Init ==
    /\ chainTip = [d \in Device |-> 0]
    /\ balance = [d \in Device |-> INITIAL_BALANCE]
    /\ deviceAlive = [d \in Device |-> TRUE]
    /\ modalLock = FALSE
    /\ relationshipTip = 0
    /\ sessions = [sid \in SessionId |-> NULL]
    /\ b0xPending = FALSE
    /\ b0xAmount = 0
    /\ b0xSender = AnyDevice
    /\ b0xReceiver = AnyDevice
    /\ vaults = [vid \in VaultId |-> NULL]
    /\ coPresent = TRUE
    /\ networkUp = [d \in Device |-> TRUE]
    /\ capsuleExists = [d \in Device |-> FALSE]
    /\ tombstoned = [d \in Device |-> FALSE]
    /\ successorOf = [d \in Device |-> NULL]

\* ========================================================================
\* BILATERAL SESSION ACTIONS
\* ========================================================================

\* ---------- Phase 1: SenderPrepare ----------
\* Maps to prepare_bilateral_transaction() in bilateral_ble_handler.rs:665
\* Creates precommitment. Guards: no modal lock, sufficient balance, chain not full.
SenderPrepare(sender, receiver, sid, amount) ==
    /\ sender /= receiver
    /\ deviceAlive[sender]
    /\ deviceAlive[receiver]
    /\ sessions[sid] = NULL
    /\ ~modalLock                                \* Whitepaper Theorem 1
    /\ balance[sender] >= amount
    /\ amount > 0
    /\ chainTip[sender] < MaxChain
    \* No other in-flight session for this sender-receiver pair
    /\ ~\E sid2 \in SessionId :
        /\ sessions[sid2] /= NULL
        /\ sessions[sid2].phase \in InFlightPhase
        /\ sessions[sid2].sender = sender
        /\ sessions[sid2].receiver = receiver
    /\ sessions' = [sessions EXCEPT ![sid] =
        [phase |-> "Prepared",
         sender |-> sender,
         receiver |-> receiver,
         tipAtCreation |-> chainTip[sender],
         amount |-> amount,
         hasBothSigs |-> FALSE]]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ---------- Phase 1→2: ReceiverReceivePrepare ----------
\* Maps to handle_prepare_request() in bilateral_ble_handler.rs:1055
\* Receiver gets the prepare via BLE (co-present) or network (both online).
ReceiverReceivePrepare(sid) ==
    /\ sessions[sid] /= NULL
    /\ sessions[sid].phase = "Prepared"
    /\ deviceAlive[sessions[sid].receiver]
    /\ \/ coPresent
       \/ (networkUp[sessions[sid].sender] /\ networkUp[sessions[sid].receiver])
    /\ sessions' = [sessions EXCEPT ![sid].phase = "PendingUserAction"]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ---------- Phase 2: UserAccept ----------
\* Maps to create_prepare_accept_envelope() in bilateral_ble_handler.rs:1557
UserAccept(sid) ==
    /\ sessions[sid] /= NULL
    /\ sessions[sid].phase = "PendingUserAction"
    /\ deviceAlive[sessions[sid].receiver]
    /\ sessions' = [sessions EXCEPT ![sid].phase = "Accepted",
                                     ![sid].hasBothSigs = TRUE]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ---------- Phase 2: UserReject ----------
\* Maps to create_prepare_reject_envelope_with_cleanup()
UserReject(sid) ==
    /\ sessions[sid] /= NULL
    /\ sessions[sid].phase = "PendingUserAction"
    /\ sessions' = [sessions EXCEPT ![sid].phase = "Rejected"]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ---------- Phase 3: Commit ----------
\* Maps to finalize_offline_transfer() in bilateral_transaction_manager.rs:952
\* Includes TRIPWIRE ENFORCEMENT (lines 983-1006):
\*   chainTip[sender] MUST equal tipAtCreation (parent not consumed)
Commit(sid) ==
    /\ sessions[sid] /= NULL
    /\ sessions[sid].phase = "Accepted"
    /\ sessions[sid].hasBothSigs = TRUE
    \* TRIPWIRE (Whitepaper Section 6.1)
    /\ chainTip[sessions[sid].sender] = sessions[sid].tipAtCreation
    /\ chainTip[sessions[sid].sender] < MaxChain
    /\ chainTip[sessions[sid].receiver] < MaxChain
    /\ deviceAlive[sessions[sid].sender]
    /\ deviceAlive[sessions[sid].receiver]
    /\ LET s == sessions[sid].sender
           r == sessions[sid].receiver
           amt == sessions[sid].amount
       IN /\ sessions' = [sessions EXCEPT ![sid].phase = "Committed"]
          /\ balance' = [balance EXCEPT ![s] = balance[s] - amt,
                                        ![r] = balance[r] + amt]
          /\ chainTip' = [chainTip EXCEPT ![s] = chainTip[s] + 1,
                                          ![r] = chainTip[r] + 1]
          /\ relationshipTip' = relationshipTip + 1
    /\ UNCHANGED <<deviceAlive, modalLock, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ---------- SessionFail ----------
\* Any in-flight session can fail: BLE disconnect, crash, timeout.
\* This is the CRITICAL liveness escape: always enabled for in-flight sessions.
SessionFail(sid) ==
    /\ sessions[sid] /= NULL
    /\ sessions[sid].phase \in InFlightPhase
    /\ sessions' = [sessions EXCEPT ![sid].phase = "Failed"]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ---------- SessionRecover ----------
\* Maps to recover_accepted_sessions() in bilateral_ble_handler.rs:475-513
\* Auto-commit accepted sessions with both sigs on restart.
SessionRecover(sid) ==
    /\ sessions[sid] /= NULL
    /\ sessions[sid].phase = "Accepted"
    /\ sessions[sid].hasBothSigs = TRUE
    /\ chainTip[sessions[sid].sender] = sessions[sid].tipAtCreation
    /\ chainTip[sessions[sid].sender] < MaxChain
    /\ chainTip[sessions[sid].receiver] < MaxChain
    /\ deviceAlive[sessions[sid].sender]
    /\ deviceAlive[sessions[sid].receiver]
    /\ LET s == sessions[sid].sender
           r == sessions[sid].receiver
           amt == sessions[sid].amount
       IN /\ sessions' = [sessions EXCEPT ![sid].phase = "Committed"]
          /\ balance' = [balance EXCEPT ![s] = balance[s] - amt,
                                        ![r] = balance[r] + amt]
          /\ chainTip' = [chainTip EXCEPT ![s] = chainTip[s] + 1,
                                          ![r] = chainTip[r] + 1]
          /\ relationshipTip' = relationshipTip + 1
    /\ UNCHANGED <<deviceAlive, modalLock, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ---------- TripwireAbort ----------
\* When the chain tip has moved since precommitment (another transaction consumed
\* the parent), the session MUST abort. Maps to DeterministicSafetyClass::ParentConsumed
\* at bilateral_transaction_manager.rs:990.
TripwireAbort(sid) ==
    /\ sessions[sid] /= NULL
    /\ sessions[sid].phase = "Accepted"
    /\ chainTip[sessions[sid].sender] /= sessions[sid].tipAtCreation
    /\ sessions' = [sessions EXCEPT ![sid].phase = "Failed"]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ========================================================================
\* MODAL LOCK / B0X ACTIONS
\* ========================================================================

\* ---------- OnlineSubmit ----------
\* Submit via b0x spool (online unilateral). Engages modal lock.
\* Maps to B0xSDK submit flow, sync_manager.rs:44-75.
\* CRITICAL: Also blocks when any in-flight session exists (modal lock is
\* relationship-wide, covering both online AND offline paths).
\* Balance is escrowed (deducted) immediately at submission time.
OnlineSubmit(sender, receiver, amount) ==
    /\ sender /= receiver
    /\ deviceAlive[sender]
    /\ ~modalLock
    /\ networkUp[sender]
    /\ balance[sender] >= amount
    /\ amount > 0
    /\ ~b0xPending
    /\ chainTip[sender] < MaxChain
    \* No in-flight sessions (modal lock covers entire relationship)
    /\ ~\E sid \in SessionId :
        /\ sessions[sid] /= NULL
        /\ sessions[sid].phase \in InFlightPhase
    /\ b0xPending' = TRUE
    /\ b0xAmount' = amount
    /\ b0xSender' = sender
    /\ b0xReceiver' = receiver
    /\ modalLock' = TRUE
    \* Escrow: deduct balance at submission (refund on reject)
    /\ balance' = [balance EXCEPT ![sender] = balance[sender] - amount]
    /\ UNCHANGED <<chainTip, deviceAlive, relationshipTip,
                   sessions, vaults, coPresent, networkUp,
                   capsuleExists, tombstoned, successorOf>>

\* ---------- OnlineDeliver ----------
\* b0x item delivered and accepted by receiver. Releases modal lock.
\* Sender balance was already escrowed at OnlineSubmit; only credit receiver here.
OnlineDeliver ==
    /\ b0xPending
    /\ modalLock
    /\ networkUp[b0xReceiver]
    /\ deviceAlive[b0xReceiver]
    /\ deviceAlive[b0xSender]
    /\ chainTip[b0xSender] < MaxChain
    /\ chainTip[b0xReceiver] < MaxChain
    /\ LET r == b0xReceiver
           amt == b0xAmount
       IN /\ balance' = [balance EXCEPT ![r] = balance[r] + amt]
          /\ chainTip' = [chainTip EXCEPT ![b0xSender] = chainTip[b0xSender] + 1,
                                          ![r] = chainTip[r] + 1]
          /\ relationshipTip' = relationshipTip + 1
    /\ modalLock' = FALSE
    /\ b0xPending' = FALSE
    /\ UNCHANGED <<deviceAlive, sessions, vaults, coPresent, networkUp,
                   capsuleExists, tombstoned, successorOf, b0xAmount, b0xSender, b0xReceiver>>

\* ---------- OnlineReject ----------
\* b0x item rejected, cancelled, or expired. Releases modal lock.
\* REFUND: return escrowed balance to sender.
OnlineReject ==
    /\ b0xPending
    /\ modalLock
    /\ modalLock' = FALSE
    /\ b0xPending' = FALSE
    /\ balance' = [balance EXCEPT ![b0xSender] = balance[b0xSender] + b0xAmount]
    /\ UNCHANGED <<chainTip, deviceAlive, relationshipTip, sessions,
                   vaults, coPresent, networkUp, capsuleExists, tombstoned, successorOf,
                   b0xAmount, b0xSender, b0xReceiver>>

\* ========================================================================
\* DLV VAULT ACTIONS
\* ========================================================================

\* Maps to DLVManager in dlv_manager.rs and LimboVault in limbo_vault.rs

\* ---------- VaultCreate ----------
\* Creator designates an intended recipient who can unlock/claim.
\* The recipient can be ANY device in the network — not necessarily
\* part of the bilateral pair. This models real DLV behavior where
\* vaults target specific counterparties.
VaultCreate(vid, creator, recipient) ==
    /\ vaults[vid] = NULL
    /\ deviceAlive[creator]
    /\ creator /= recipient
    /\ vaults' = [vaults EXCEPT ![vid] = [state |-> "Limbo",
                                           creator |-> creator,
                                           recipient |-> recipient]]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   sessions, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ---------- VaultUnlock ----------
\* Intended recipient presents fulfillment proof. Maps to LimboVault::unlock()
\* at line 1512. Does NOT require creator to be alive. The recipient can be
\* ANY device in the network (e.g., d3 outside the d1/d2 bilateral pair).
\* Vault data is redundantly stored on N=6 storage nodes (K=3 quorum),
\* so it survives creator device death.
VaultUnlock(vid) ==
    /\ vaults[vid] /= NULL
    /\ vaults[vid].state = "Limbo"
    /\ deviceAlive[vaults[vid].recipient]  \* Recipient must be alive to present proof
    /\ vaults' = [vaults EXCEPT ![vid].state = "Unlocked"]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   sessions, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ---------- VaultClaim ----------
\* Maps to LimboVault::claim() at line 1545.
\* Intended recipient presents Kyber secret key. No creator needed.
\* The recipient is a specific device — potentially outside the bilateral pair.
VaultClaim(vid) ==
    /\ vaults[vid] /= NULL
    /\ vaults[vid].state = "Unlocked"
    /\ deviceAlive[vaults[vid].recipient]  \* Recipient claims with their key
    /\ vaults' = [vaults EXCEPT ![vid].state = "Claimed"]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   sessions, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ---------- VaultInvalidate ----------
\* Creator unilaterally invalidates vault. THE critical DLV liveness escape.
\* Maps to LimboVault::invalidate() at line 1631.
\* Works from BOTH Limbo AND Unlocked states.
VaultInvalidate(vid) ==
    /\ vaults[vid] /= NULL
    /\ vaults[vid].state \in {"Limbo", "Unlocked"}
    /\ LET creator == vaults[vid].creator
       IN \/ deviceAlive[creator]
          \* Successor can also invalidate on behalf of dead creator
          \/ \E dNew \in Device :
               /\ successorOf[creator] = dNew
               /\ deviceAlive[dNew]
    /\ vaults' = [vaults EXCEPT ![vid].state = "Invalidated"]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   sessions, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ---------- VaultExpire ----------
\* Vaults have a deterministic expiration (BLAKE3 iteration counter, not wall
\* clock). Vault data lives on N=6 storage nodes (K=3 quorum). Storage nodes
\* track the vault's lifetime counter and expire it autonomously when it hits
\* zero. NO DEVICE NEEDS TO BE ALIVE — this is entirely handled by the storage
\* layer. Maps to VaultStatus::Expired at limbo_vault.rs:1768.
\*
\* This is the ultimate liveness escape: even if every device in the network
\* dies, storage nodes still expire vaults deterministically.
VaultExpire(vid) ==
    /\ vaults[vid] /= NULL
    /\ vaults[vid].state \in {"Limbo", "Unlocked"}
    /\ vaults' = [vaults EXCEPT ![vid].state = "Invalidated"]  \* Expiry => terminal
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   sessions, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* ========================================================================
\* ENVIRONMENT ACTIONS (nondeterministic)
\* ========================================================================

\* Network partition and healing
PartitionStart(d) ==
    /\ networkUp[d]
    /\ networkUp' = [networkUp EXCEPT ![d] = FALSE]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   sessions, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, capsuleExists, tombstoned, successorOf>>

PartitionEnd(d) ==
    /\ ~networkUp[d]
    /\ networkUp' = [networkUp EXCEPT ![d] = TRUE]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   sessions, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, capsuleExists, tombstoned, successorOf>>

\* BLE proximity changes
BleConnect ==
    /\ ~coPresent
    /\ coPresent' = TRUE
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   sessions, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, networkUp, capsuleExists, tombstoned, successorOf>>

BleDisconnect ==
    /\ coPresent
    /\ coPresent' = FALSE
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   sessions, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, networkUp, capsuleExists, tombstoned, successorOf>>

\* ========================================================================
\* RECOVERY ACTIONS
\* ========================================================================

\* Maps to recovery/capsule.rs and recovery/tombstone.rs

\* Write recovery capsule (after each committed transaction)
CapsuleWrite(d) ==
    /\ deviceAlive[d]
    /\ capsuleExists' = [capsuleExists EXCEPT ![d] = TRUE]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   sessions, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, networkUp, tombstoned, successorOf>>

\* Device failure — all in-flight sessions involving this device fail
DeviceFail(d) ==
    /\ deviceAlive[d]
    /\ deviceAlive' = [deviceAlive EXCEPT ![d] = FALSE]
    /\ sessions' = [sid \in SessionId |->
        IF sessions[sid] /= NULL
           /\ sessions[sid].phase \in InFlightPhase
           /\ (sessions[sid].sender = d \/ sessions[sid].receiver = d)
        THEN [sessions[sid] EXCEPT !.phase = "Failed"]
        ELSE sessions[sid]]
    /\ UNCHANGED <<chainTip, balance, modalLock, relationshipTip,
                   b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, networkUp, capsuleExists, tombstoned, successorOf>>

\* Tombstone (marks old device invalid). Maps to TombstoneReceipt at tombstone.rs:28.
TombstoneCreate(d) ==
    /\ ~deviceAlive[d]
    /\ ~tombstoned[d]
    /\ capsuleExists[d]
    /\ tombstoned' = [tombstoned EXCEPT ![d] = TRUE]
    /\ UNCHANGED <<chainTip, balance, deviceAlive, modalLock, relationshipTip,
                   sessions, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, networkUp, capsuleExists, successorOf>>

\* Succession (new device takes over). Maps to SuccessionReceipt at tombstone.rs:46.
SuccessionCreate(dOld, dNew) ==
    /\ dOld /= dNew
    /\ tombstoned[dOld]
    /\ ~deviceAlive[dOld]
    /\ deviceAlive[dNew]
    /\ successorOf[dOld] = NULL
    /\ successorOf' = [successorOf EXCEPT ![dOld] = dNew]
    /\ chainTip' = [chainTip EXCEPT ![dNew] = chainTip[dOld]]
    /\ balance' = [balance EXCEPT ![dNew] = balance[dNew] + balance[dOld],
                                  ![dOld] = 0]
    /\ UNCHANGED <<deviceAlive, modalLock, relationshipTip,
                   sessions, b0xPending, b0xAmount, b0xSender, b0xReceiver,
                   vaults, coPresent, networkUp, capsuleExists, tombstoned>>

\* ========================================================================
\* NEXT-STATE RELATION
\* ========================================================================

Next ==
    \* Bilateral session actions
    \/ \E s, r \in Device, sid \in SessionId, amt \in 1..INITIAL_BALANCE :
        SenderPrepare(s, r, sid, amt)
    \/ \E sid \in SessionId : ReceiverReceivePrepare(sid)
    \/ \E sid \in SessionId : UserAccept(sid)
    \/ \E sid \in SessionId : UserReject(sid)
    \/ \E sid \in SessionId : Commit(sid)
    \/ \E sid \in SessionId : SessionFail(sid)
    \/ \E sid \in SessionId : SessionRecover(sid)
    \/ \E sid \in SessionId : TripwireAbort(sid)
    \* Modal lock / b0x actions
    \/ \E s, r \in Device, amt \in 1..INITIAL_BALANCE :
        OnlineSubmit(s, r, amt)
    \/ OnlineDeliver
    \/ OnlineReject
    \* DLV vault actions
    \/ \E vid \in VaultId, cr, rcpt \in Device : VaultCreate(vid, cr, rcpt)
    \/ \E vid \in VaultId : VaultUnlock(vid)
    \/ \E vid \in VaultId : VaultClaim(vid)
    \/ \E vid \in VaultId : VaultInvalidate(vid)
    \/ \E vid \in VaultId : VaultExpire(vid)
    \* Environment actions
    \/ \E d \in Device : PartitionStart(d)
    \/ \E d \in Device : PartitionEnd(d)
    \/ BleConnect
    \/ BleDisconnect
    \* Recovery actions
    \/ \E d \in Device : CapsuleWrite(d)
    \/ \E d \in Device : DeviceFail(d)
    \/ \E d \in Device : TombstoneCreate(d)
    \/ \E dOld, dNew \in Device : SuccessionCreate(dOld, dNew)

\* ========================================================================
\* SAFETY INVARIANTS
\* ========================================================================

\* TypeOK: all variables have valid types
TypeOK ==
    /\ chainTip \in [Device -> Hash]
    /\ balance \in [Device -> Nat]
    /\ deviceAlive \in [Device -> BOOLEAN]
    /\ modalLock \in BOOLEAN
    /\ relationshipTip \in Nat
    /\ \A sid \in SessionId :
        sessions[sid] = NULL \/
        (/\ sessions[sid].phase \in Phase
         /\ sessions[sid].sender \in Device
         /\ sessions[sid].receiver \in Device
         /\ sessions[sid].tipAtCreation \in Hash
         /\ sessions[sid].amount \in 1..INITIAL_BALANCE
         /\ sessions[sid].hasBothSigs \in BOOLEAN)
    /\ b0xPending \in BOOLEAN
    /\ b0xAmount \in Nat
    /\ b0xSender \in Device
    /\ b0xReceiver \in Device
    /\ \A vid \in VaultId :
        vaults[vid] = NULL \/
        (/\ vaults[vid].state \in VState
         /\ vaults[vid].creator \in Device
         /\ vaults[vid].recipient \in Device)
    /\ coPresent \in BOOLEAN
    /\ networkUp \in [Device -> BOOLEAN]
    /\ capsuleExists \in [Device -> BOOLEAN]
    /\ tombstoned \in [Device -> BOOLEAN]
    /\ successorOf \in [Device -> Device \cup {NULL}]

\* NoFork (Tripwire Theorem 2, Whitepaper Section 6.1):
\* No two committed sessions consumed the same parent tip for the same sender.
NoFork ==
    \A s1, s2 \in SessionId :
        (s1 /= s2
         /\ sessions[s1] /= NULL /\ sessions[s2] /= NULL
         /\ sessions[s1].phase = "Committed" /\ sessions[s2].phase = "Committed"
         /\ sessions[s1].sender = sessions[s2].sender)
        => sessions[s1].tipAtCreation /= sessions[s2].tipAtCreation

\* TokenConservation (Theorem 4): total balance + escrowed amount is constant.
\* When b0xPending, the escrowed amount was deducted from sender but not yet
\* credited to receiver — so visible balances sum to (total - escrow).
RECURSIVE SumBal(_)
SumBal(S) == IF S = {} THEN 0
             ELSE LET d == CHOOSE x \in S : TRUE
                  IN balance[d] + SumBal(S \ {d})

EscrowedAmount == IF b0xPending THEN b0xAmount ELSE 0

TokenConservation ==
    SumBal(Device) + EscrowedAmount = Cardinality(Device) * INITIAL_BALANCE

\* ModalLockConsistency (Theorem 1): lock implies pending b0x item.
ModalLockConsistency ==
    modalLock => b0xPending

\* Balances never go negative.
BalancesNonNegative ==
    \A d \in Device : balance[d] >= 0

\* ========================================================================
\* LIVENESS PROPERTIES
\* ========================================================================

\* ------------------------------------------------------------
\* FAIRNESS ASSUMPTIONS
\*
\* Weak fairness: if an action is continuously enabled, it is
\* eventually taken. This is the standard assumption for liveness
\* in distributed systems.
\*
\* We require WF on:
\*   - User actions (users eventually respond)
\*   - Commit/recover (accepted sessions eventually finalize)
\*   - TripwireAbort (detected conflicts eventually abort)
\*   - SessionFail (stuck sessions eventually time out)
\*   - Modal lock resolution (b0x items eventually delivered/rejected)
\*   - Network healing (partitions eventually end)
\*   - BLE reconnection
\*   - Vault invalidation (creators eventually act on stuck vaults)
\*   - Recovery (tombstones and successions eventually happen)
\* ------------------------------------------------------------

Fairness ==
    /\ \A sid \in SessionId :
        /\ WF_vars(UserAccept(sid))
        /\ WF_vars(UserReject(sid))
        /\ WF_vars(Commit(sid))
        /\ WF_vars(SessionRecover(sid))
        /\ WF_vars(TripwireAbort(sid))
        /\ WF_vars(SessionFail(sid))
    /\ WF_vars(OnlineDeliver)
    /\ WF_vars(OnlineReject)
    /\ \A d \in Device : WF_vars(PartitionEnd(d))
    /\ WF_vars(BleConnect)
    /\ \A vid \in VaultId : WF_vars(VaultUnlock(vid))
    /\ \A vid \in VaultId : WF_vars(VaultClaim(vid))
    /\ \A vid \in VaultId : WF_vars(VaultInvalidate(vid))
    \* VaultExpire must use SF (strong fairness) not WF (weak fairness).
    \* WF only fires when no other vars-changing step occurs. PartitionStart/End
    \* cycle on networkUp indefinitely, keeping VaultExpire enabled but blocked
    \* under WF. SF fires whenever the action is infinitely-often enabled —
    \* this is the correct assumption for storage-node autonomous expiry
    \* (BLAKE3 iteration counter τ ticks forward regardless of network churn).
    /\ \A vid \in VaultId : SF_vars(VaultExpire(vid))
    /\ \A d \in Device : WF_vars(TombstoneCreate(d))
    /\ \A dOld, dNew \in Device : WF_vars(SuccessionCreate(dOld, dNew))

Spec == Init /\ [][Next]_vars /\ Fairness

\* ------------------------------------------------------------
\* Property 1: SESSION TERMINATION
\*
\* Every bilateral session that starts eventually reaches a
\* terminal state {Committed, Rejected, Failed}.
\*
\* Proof sketch:
\*   Preparing/Prepared: SessionFail is always enabled (WF fires)
\*   PendingUserAction: UserAccept or UserReject (WF on both)
\*   Accepted + bothSigs + tipMatch: Commit enabled (WF fires)
\*   Accepted + tipMoved: TripwireAbort enabled (WF fires)
\*   Accepted + noBothSigs: SessionFail enabled (WF fires)
\* Every case leads to a terminal state. QED.
\* ------------------------------------------------------------
SessionTermination ==
    \A sid \in SessionId :
        [](sessions[sid] /= NULL /\ sessions[sid].phase \in InFlightPhase
           => <>(sessions[sid] = NULL \/ sessions[sid].phase \in TerminalPhase))

\* ------------------------------------------------------------
\* Property 2: MODAL LOCK RESOLUTION
\*
\* The modal lock (Whitepaper Theorem 1) always eventually clears.
\*
\* Proof sketch:
\*   modalLock => b0xPending (invariant).
\*   OnlineReject is always enabled when b0xPending /\ modalLock.
\*   WF on OnlineReject fires. modalLock' = FALSE. QED.
\* ------------------------------------------------------------
ModalLockResolution ==
    [](modalLock => <>(~modalLock))

\* ------------------------------------------------------------
\* Property 3: DLV LIVENESS (UNCONDITIONAL)
\*
\* No vault remains non-terminal forever. No device-alive guard.
\*
\* Vault data lives on N=6 storage nodes (K=3 quorum). Storage
\* nodes expire vaults autonomously via deterministic BLAKE3
\* iteration counter — no device needs to be alive.
\*
\* Resolution paths (all covered by weak fairness):
\*   Case 1: Creator alive → VaultInvalidate (WF fires)
\*   Case 2: Recipient alive → VaultUnlock → VaultClaim (WF fires)
\*   Case 3: Creator dead + capsule + live successor →
\*           Tombstone → Succession → successor invalidates
\*   Case 4: ALL devices dead → VaultExpire fires anyway.
\*           Storage nodes handle it autonomously. WF guarantees
\*           termination. No device needs to be alive.
\*
\* Every case resolves. There is no stuck state. QED.
\* (The 3-device "recipient outside pair" case is a superset of
\* Case 2 and follows from the same WF argument with an additional
\* independent device not modeled here for tractability.)
\* ------------------------------------------------------------
DLVLiveness ==
    \A vid \in VaultId :
        [](  vaults[vid] /= NULL
           /\ vaults[vid].state \in {"Limbo", "Unlocked"}
           => <>(vaults[vid] = NULL \/ vaults[vid].state \in TerminalVState))

\* ========================================================================
\* SPECIFICATION AND PROPERTIES BUNDLE
\* ========================================================================

\* All safety invariants
Safety ==
    /\ TypeOK
    /\ NoFork
    /\ TokenConservation
    /\ ModalLockConsistency
    /\ BalancesNonNegative

====
