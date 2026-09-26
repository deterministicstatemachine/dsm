---- MODULE DSM_OfflineFinality ----
EXTENDS Integers, Sequences, FiniteSets, TLC

(***************************************************************************
  DSM Offline Finality — the offline bilateral step between two devices
  =======================================================================

  One relationship between two devices. Either device may propose a step
  to the other, and each step runs prepare -> accept -> confirm -> ack:

      proposer                          receiver
      Prepared        -- prepare -->    PendingUser  (its user decides)
                      <-- response --   Accepted     (or a signed rejection)
      ConfirmPending  -- confirm -->    Committed    (commits, then answers)
      Committed       <--- ack -----

  The receiver commits on the confirm and the proposer on the ack: two
  commits, on two devices, at two moments. Atomicity is therefore not "both
  move in one step" but BOTH-OR-NEITHER: a step committed on one device is
  committed on the other, or is still owed there by a proposer that can no
  longer end it and can still commit it.

  What the model holds the code to (dsm_sdk bluetooth/bilateral_ble_handler.rs):

    * Every transition is durable before the frame it owes leaves: Core
      decides, one SQLite transaction writes the phase and everything the
      step commits, and only then does the frame go to the carrier. So the
      durable phase IS a device's state, and a restart changes nothing it
      holds — it takes every step up again (restore_sessions_from_storage).
      A crash loses only frames in the air, which a lost link loses too.
    * A lost link fails nothing. The link is up or down; losing it drops the
      frames in the air. While it is up each device delivers what its phase
      owes (frames_owed_to): the prepare while Prepared, the response while
      Accepted, the confirm while ConfirmPending.
    * A frame delivered again is answered from durable state: an acceptance
      answers a repeated prepare with its response and a rejection with its
      signed rejection; a confirmed step answers a repeated response with its
      confirm and a cancelled one with its cancellation; a committed step
      answers a repeated confirm with its ack (the lost ack,
      answer_committed_confirm).
    * A step ends without committing only on a signed rejection (the
      receiver's), a signed cancellation (the proposer's, and only before
      its confirm), or invalid evidence. Never on time.
    * One step at a time per relationship, at BOTH doors: a device with a
      step in flight neither proposes (ensure_counterparty_ready_for_prepare)
      nor takes the peer's proposal — it answers that with a signed
      rejection, and keeps it, so the proposal delivered again gets the same
      answer.
    * Each commit is guarded by the tripwire: the device's relationship tip
      is the step's parent — for the receiver, the tip its precommitment was
      made on; for the proposer, the head its confirm was signed from (the
      root its receipt names).

  Implementation switches. DSM_OfflineFinality.cfg sets each to the code's
  behaviour. Each falsification config flips exactly one and names the
  invariant that then fails, so every rule above is shown load-bearing:

    FramesAfterDurable            FALSE: the confirm leaves before
                                  ConfirmPending is durable and the proposer
                                  restarts before writing it -> NoHalfCommit
    CancelOnlyBeforeConfirm       FALSE: a proposer may cancel after its
                                  confirm -> NoHalfCommit
    LinkLossFailsNothing          FALSE: losing the link fails every step in
                                  flight (the removed disconnect handler)
                                  -> NoHalfCommit
    ReceiverRefusesWhileInFlight  FALSE: a device with a step in flight still
                                  takes the peer's proposal. Two proposals
                                  that cross each commit on its receiver: two
                                  successors of one tip -> NoFork

  Out of scope, recorded open in specs/requirements/CONFORMANCE_GAPS.md
  §6.28: a device whose head moves through ANOTHER relationship between its
  confirm and its commit cannot commit (the receipt it signed names its whole
  device root). This model has one relationship.
***************************************************************************)

CONSTANTS
    Device,                        \* the relationship's two devices
    StepsPerDevice,                \* steps each device may propose
    INITIAL_BALANCE,               \* each device's balance; a step moves 1
    FramesAfterDurable,
    CancelOnlyBeforeConfirm,
    LinkLossFailsNothing,
    ReceiverRefusesWhileInFlight

ASSUME Cardinality(Device) = 2
ASSUME StepsPerDevice \in Nat \ {0}
ASSUME INITIAL_BALANCE \in Nat
ASSUME {FramesAfterDurable, CancelOnlyBeforeConfirm, LinkLossFailsNothing,
        ReceiverRefusesWhileInFlight} \subseteq BOOLEAN

\* A step is named by its proposer and a number.
Step == Device \X (1..StepsPerDevice)
Proposer(s) == s[1]
Peer(d) == CHOOSE e \in Device : e # d
Receiver(s) == Peer(Proposer(s))

NoParent == -1

\* A device's phase for a step:
\*   None            it holds nothing for the step
\*   Prepared        proposer: proposed, awaiting the response
\*   ConfirmPending  proposer: confirmed, awaiting the ack
\*   PendingUser     receiver: holding the proposal for its user
\*   Accepted        receiver: accepted, awaiting the confirm
\*   Rejected        it signed the step's end (a rejection or a
\*                   cancellation), which it keeps as its answer
\*   Ended           the peer's signed rejection or cancellation ended it
\*   Committed       the step is in its chain
\*   Failed          ended with no signed end (only the removed disconnect
\*                   handler did this: LinkLossFailsNothing = FALSE)
Phase == {"None", "Prepared", "ConfirmPending", "PendingUser", "Accepted",
          "Rejected", "Ended", "Committed", "Failed"}
InFlightPhase == {"Prepared", "ConfirmPending", "PendingUser", "Accepted"}

Kind == {"prepare", "response", "reject", "cancel", "confirm", "ack"}
Msg(k, s) == [kind |-> k, step |-> s]

VARIABLES
    chain,    \* chain[d]: the steps d has committed on the relationship, in order
    phase,    \* phase[d][s]: d's durable phase for step s
    parent,   \* parent[s]: the relationship tip s was proposed on
    net,      \* the frames in the air
    link      \* whether the two devices are linked

vars == <<chain, phase, parent, net, link>>

Tip(d) == Len(chain[d])
InChain(d, s) == \E i \in 1..Len(chain[d]) : chain[d][i] = s
Balance(d) ==
    INITIAL_BALANCE
      - Cardinality({i \in 1..Len(chain[d]) : Proposer(chain[d][i]) = d})
      + Cardinality({i \in 1..Len(chain[d]) : Proposer(chain[d][i]) # d})
InFlight(d) == \E s \in Step : phase[d][s] \in InFlightPhase

\* A frame leaves only while the devices are linked; one that cannot leave
\* is still owed by the phase that produced it.
Emit(k, s) == net' = IF link THEN net \cup {Msg(k, s)} ELSE net
\* A frame taken off the air, answered with `k` (the answer leaves with it).
Answer(m, k) == net' = (net \ {m}) \cup {Msg(k, m.step)}
Consume(m) == net' = net \ {m}

Init ==
    /\ chain = [d \in Device |-> <<>>]
    /\ phase = [d \in Device |-> [s \in Step |-> "None"]]
    /\ parent = [s \in Step |-> NoParent]
    /\ net = {}
    /\ link = TRUE

\* ------------------------------------------------------------------------
\* The proposer's door: one step at a time. prepare_bilateral_transaction
\* after ensure_counterparty_ready_for_prepare; the proposal is durable, with
\* its prepare owed, before the prepare leaves.
\* ------------------------------------------------------------------------
Propose(s) ==
    LET d == Proposer(s) IN
    /\ phase[d][s] = "None"
    /\ parent[s] = NoParent
    /\ ~InFlight(d)
    /\ Balance(d) >= 1
    /\ phase' = [phase EXCEPT ![d][s] = "Prepared"]
    /\ parent' = [parent EXCEPT ![s] = Tip(d)]
    /\ Emit("prepare", s)
    /\ UNCHANGED <<chain, link>>

\* ------------------------------------------------------------------------
\* The receiver's door (handle_prepare_request). A step it already holds is
\* answered from its phase. A new one is refused, with a signed rejection it
\* keeps, while the receiver has a step of its own in flight; refused, with a
\* signed rejection, when it does not extend the receiver's tip (the tip
\* never comes back, so that answer need not be kept); otherwise held for the
\* user.
\* ------------------------------------------------------------------------
RecvPrepare(s) ==
    LET r == Receiver(s)
        m == Msg("prepare", s)
    IN
    /\ link
    /\ m \in net
    /\ CASE phase[r][s] = "Accepted" ->
              /\ Answer(m, "response")
              /\ UNCHANGED phase
         [] phase[r][s] = "Rejected" ->
              /\ Answer(m, "reject")
              /\ UNCHANGED phase
         [] phase[r][s] = "None" /\ ReceiverRefusesWhileInFlight /\ InFlight(r) ->
              /\ phase' = [phase EXCEPT ![r][s] = "Rejected"]
              /\ Answer(m, "reject")
         [] phase[r][s] = "None" /\ Tip(r) # parent[s] ->
              /\ Answer(m, "reject")
              /\ UNCHANGED phase
         [] phase[r][s] = "None" ->
              /\ phase' = [phase EXCEPT ![r][s] = "PendingUser"]
              /\ Consume(m)
         [] OTHER ->
              \* PendingUser, Ended, Committed, Failed: nothing to answer
              /\ Consume(m)
              /\ UNCHANGED phase
    /\ UNCHANGED <<chain, parent, link>>

\* The receiver's user accepts: Accepted is durable, with the response owed,
\* before the response leaves.
UserAccept(s) ==
    LET r == Receiver(s) IN
    /\ phase[r][s] = "PendingUser"
    /\ phase' = [phase EXCEPT ![r][s] = "Accepted"]
    /\ Emit("response", s)
    /\ UNCHANGED <<chain, parent, link>>

\* The receiver's user rejects: a signed rejection, kept.
UserReject(s) ==
    LET r == Receiver(s) IN
    /\ phase[r][s] = "PendingUser"
    /\ phase' = [phase EXCEPT ![r][s] = "Rejected"]
    /\ Emit("reject", s)
    /\ UNCHANGED <<chain, parent, link>>

\* ------------------------------------------------------------------------
\* The proposer takes the response (handle_prepare_response). From Prepared
\* it confirms: ConfirmPending is durable, with the confirm owed, before the
\* confirm leaves (send_bilateral_confirm).
\* ------------------------------------------------------------------------
RecvResponse(s) ==
    LET p == Proposer(s)
        m == Msg("response", s)
    IN
    /\ link
    /\ m \in net
    /\ CASE phase[p][s] = "Prepared" ->
              /\ phase' = [phase EXCEPT ![p][s] = "ConfirmPending"]
              /\ Answer(m, "confirm")
         [] phase[p][s] = "ConfirmPending" ->
              /\ Answer(m, "confirm")
              /\ UNCHANGED phase
         [] phase[p][s] = "Rejected" ->
              /\ Answer(m, "cancel")
              /\ UNCHANGED phase
         [] OTHER ->
              /\ Consume(m)
              /\ UNCHANGED phase
    /\ UNCHANGED <<chain, parent, link>>

\* FramesAfterDurable = FALSE: the confirm leaves first and the proposer
\* restarts before ConfirmPending is written. The confirm is out; the
\* proposer holds Prepared.
RecvResponseFrameFirst(s) ==
    LET p == Proposer(s)
        m == Msg("response", s)
    IN
    /\ ~FramesAfterDurable
    /\ link
    /\ m \in net
    /\ phase[p][s] = "Prepared"
    /\ Answer(m, "confirm")
    /\ UNCHANGED <<chain, phase, parent, link>>

\* The proposer takes the receiver's signed rejection (handle_prepare_reject):
\* it ends only a proposal not yet confirmed.
RecvReject(s) ==
    LET p == Proposer(s)
        m == Msg("reject", s)
    IN
    /\ link
    /\ m \in net
    /\ Consume(m)
    /\ phase' = IF phase[p][s] = "Prepared"
                THEN [phase EXCEPT ![p][s] = "Ended"]
                ELSE phase
    /\ UNCHANGED <<chain, parent, link>>

\* The proposer cancels a proposal it has not confirmed (cancel_proposal): a
\* signed cancellation, kept as its answer to the receiver's next frame.
Cancel(s) ==
    LET p == Proposer(s) IN
    /\ \/ phase[p][s] = "Prepared"
       \/ ~CancelOnlyBeforeConfirm /\ phase[p][s] = "ConfirmPending"
    /\ phase' = [phase EXCEPT ![p][s] = "Rejected"]
    /\ Emit("cancel", s)
    /\ UNCHANGED <<chain, parent, link>>

\* The receiver takes the proposer's signed cancellation: it ends a step the
\* receiver holds and has not committed.
RecvCancel(s) ==
    LET r == Receiver(s)
        m == Msg("cancel", s)
    IN
    /\ link
    /\ m \in net
    /\ Consume(m)
    /\ phase' = IF phase[r][s] \in {"PendingUser", "Accepted"}
                THEN [phase EXCEPT ![r][s] = "Ended"]
                ELSE phase
    /\ UNCHANGED <<chain, parent, link>>

\* ------------------------------------------------------------------------
\* The receiver takes the confirm (handle_confirm_request): it commits in one
\* transaction and only then answers with its ack. A committed step answers
\* the confirm again with its ack (answer_committed_confirm).
\* ------------------------------------------------------------------------
RecvConfirm(s) ==
    LET r == Receiver(s)
        m == Msg("confirm", s)
    IN
    /\ link
    /\ m \in net
    /\ CASE phase[r][s] = "Accepted" /\ Tip(r) = parent[s] ->
              /\ chain' = [chain EXCEPT ![r] = Append(@, s)]
              /\ phase' = [phase EXCEPT ![r][s] = "Committed"]
              /\ Answer(m, "ack")
         [] phase[r][s] = "Committed" ->
              /\ Answer(m, "ack")
              /\ UNCHANGED <<chain, phase>>
         [] OTHER ->
              /\ Consume(m)
              /\ UNCHANGED <<chain, phase>>
    /\ UNCHANGED <<parent, link>>

\* The proposer takes the ack (handle_commit_response): it commits the step
\* its confirm was signed from. An ack that does not hold against its heads
\* commits nothing and leaves the step awaiting its ack.
RecvAck(s) ==
    LET p == Proposer(s)
        m == Msg("ack", s)
    IN
    /\ link
    /\ m \in net
    /\ Consume(m)
    /\ IF phase[p][s] = "ConfirmPending" /\ Tip(p) = parent[s]
       THEN /\ chain' = [chain EXCEPT ![p] = Append(@, s)]
            /\ phase' = [phase EXCEPT ![p][s] = "Committed"]
       ELSE UNCHANGED <<chain, phase>>
    /\ UNCHANGED <<parent, link>>

\* ------------------------------------------------------------------------
\* The link. While it is up each device delivers what its phase owes
\* (deliver_owed_frames on connect). Losing it drops the frames in the air
\* and, in the code, fails nothing.
\* ------------------------------------------------------------------------
Owed(d, s) ==
    CASE phase[d][s] = "Prepared" -> "prepare"
      [] phase[d][s] = "Accepted" -> "response"
      [] phase[d][s] = "ConfirmPending" -> "confirm"
      [] OTHER -> "none"

Resend(d, s) ==
    /\ link
    /\ Owed(d, s) # "none"
    /\ Msg(Owed(d, s), s) \notin net
    /\ net' = net \cup {Msg(Owed(d, s), s)}
    /\ UNCHANGED <<chain, phase, parent, link>>

LinkDown ==
    /\ link
    /\ link' = FALSE
    /\ net' = {}
    /\ phase' = IF LinkLossFailsNothing
                THEN phase
                ELSE [d \in Device |-> [s \in Step |->
                        IF phase[d][s] \in InFlightPhase THEN "Failed"
                                                         ELSE phase[d][s]]]
    /\ UNCHANGED <<chain, parent>>

LinkUp ==
    /\ ~link
    /\ link' = TRUE
    /\ UNCHANGED <<chain, phase, parent, net>>

Next ==
    \/ \E s \in Step :
          \/ Propose(s)
          \/ RecvPrepare(s)
          \/ UserAccept(s)
          \/ UserReject(s)
          \/ RecvResponse(s)
          \/ RecvResponseFrameFirst(s)
          \/ RecvReject(s)
          \/ Cancel(s)
          \/ RecvCancel(s)
          \/ RecvConfirm(s)
          \/ RecvAck(s)
    \/ \E d \in Device, s \in Step : Resend(d, s)
    \/ LinkDown
    \/ LinkUp

\* Fairness: a user eventually decides on a proposal it holds, and while the
\* link is up an owed frame is eventually sent and a frame in the air is
\* eventually taken. Proposing, cancelling and the link itself are free.
Fairness ==
    /\ \A s \in Step :
          /\ WF_vars(UserAccept(s) \/ UserReject(s))
          /\ WF_vars(RecvPrepare(s))
          /\ WF_vars(RecvResponse(s))
          /\ WF_vars(RecvReject(s))
          /\ WF_vars(RecvCancel(s))
          /\ WF_vars(RecvConfirm(s))
          /\ WF_vars(RecvAck(s))
    /\ \A d \in Device, s \in Step : WF_vars(Resend(d, s))

Spec == Init /\ [][Next]_vars /\ Fairness

\* ========================================================================
\* SAFETY
\* ========================================================================

TypeOK ==
    /\ chain \in [Device -> Seq(Step)]
    /\ phase \in [Device -> [Step -> Phase]]
    /\ parent \in [Step -> {NoParent} \cup Nat]
    /\ net \subseteq [kind : Kind, step : Step]
    /\ link \in BOOLEAN

\* The two devices hold one relationship chain: one is a prefix of the other.
NoFork ==
    \A d \in Device :
        Len(chain[d]) <= Len(chain[Peer(d)])
            => SubSeq(chain[Peer(d)], 1, Len(chain[d])) = chain[d]

\* Both-or-neither: a step committed on one device is committed on the other,
\* or is owed there by a proposer that can no longer end it (it is past its
\* confirm) and can still commit it (its tip is the step's parent).
NoHalfCommit ==
    \A d \in Device, s \in Step :
        InChain(d, s) =>
            \/ InChain(Peer(d), s)
            \/ /\ d = Receiver(s)
               /\ phase[Proposer(s)][s] = "ConfirmPending"
               /\ Tip(Proposer(s)) = parent[s]

\* Tripwire (spec §53): no two committed steps share a parent — on either
\* device.
TripwireGuaranteesUniqueness ==
    \A s, t \in Step :
        (/\ s # t
         /\ \E d \in Device : InChain(d, s)
         /\ \E d \in Device : InChain(d, t))
        => parent[s] # parent[t]

\* Every committed step sits directly on its parent.
CommitsExtendTheirParent ==
    \A d \in Device : \A i \in 1..Len(chain[d]) : parent[chain[d][i]] = i - 1

\* One step at a time: a device holds at most one step in flight.
OneStepInFlight ==
    \A d \in Device :
        Cardinality({s \in Step : phase[d][s] \in InFlightPhase}) <= 1

\* With no step in flight anywhere, no value was made or lost.
TokenConservation ==
    (\A d \in Device : ~InFlight(d))
        => LET d == CHOOSE x \in Device : TRUE
           IN Balance(d) + Balance(Peer(d)) = 2 * INITIAL_BALANCE

BalancesNonNegative == \A d \in Device : Balance(d) >= 0

\* The durable boundary, frame by frame: a confirm in the air was sent by a
\* proposer whose ConfirmPending is durable; an ack by a receiver whose
\* commit is.
ConfirmFollowsDurableConfirm ==
    \A s \in Step :
        Msg("confirm", s) \in net
            => phase[Proposer(s)][s] \in {"ConfirmPending", "Committed"}

AckFollowsDurableCommit ==
    \A s \in Step : Msg("ack", s) \in net => InChain(Receiver(s), s)

\* A committed step stays committed: each chain only grows.
ChainsOnlyGrow ==
    [][\A d \in Device :
          /\ Len(chain[d]) <= Len(chain'[d])
          /\ SubSeq(chain'[d], 1, Len(chain[d])) = chain[d]]_vars

\* Non-vacuity witnesses. Each is false in some reachable state, and its
\* *Reachable config expects TLC to find one: both steps commit on both
\* devices, and the two devices' proposals are in flight at once (they
\* cross), so the invariants above are checked over those states.
NeverCommittedOnBoth == ~(\A s \in Step : \A d \in Device : InChain(d, s))
NeverCrossed == ~(\A s \in Step : phase[Proposer(s)][s] = "Prepared")

\* ========================================================================
\* LIVENESS
\* ========================================================================

Proposed(s) == parent[s] # NoParent
Settled(s) == \A d \in Device : phase[d][s] \notin InFlightPhase

\* If the link eventually stays up, every proposed step settles on both
\* devices — committed on both (NoHalfCommit) or ended on both. Nothing here
\* ends a step on time or on a lost link.
SessionTermination ==
    (<>[]link) => \A s \in Step : Proposed(s) ~> Settled(s)

====
