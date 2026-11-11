# A relationship opens and ends on its own chain

Owner, 2026-11-10: "They shouldn't be able to send to someone they haven't
added", "they shouldn't be able to send to someone that hasn't added them
either", "The first transaction should have to be established on both sides,
the moneyless one", "there still should be a way to refuse it later on too, so
you should be able to terminate a relationship as well", "I want you to
implement the chain step", "Need to do it for both the initial and then the
rejection as well."

This note is the design. It changes nothing about acceptance: a receiver
validates a step from that step's own parent (Amendment A14), and these two
steps are validated exactly that way.

## What is true today

- Adding a contact installs the relationship's leaf at `h_0` on the adder's
  device alone (`CoreSDK::establish_relationship`). No step, no signature from
  the other side, nothing travels. The other side may never have heard of it.
- A sender may send the moment it has added the contact. The recipient reads
  only its contacts' spools, so a send to a device that has not added the
  sender lands on the nodes and is never read, and the sender shows Sent
  (proven on the fleet, 2026-11-10).
- The one moneyless step on a bilateral chain is recovery's re-establish, a
  `CreateRelationship` operation co-signed over Bluetooth. The online receive
  path takes nothing but a `Transfer`.
- Nothing ends a relationship. Unpair is Bluetooth only. There is no
  "terminated" state anywhere.
- The spec already says it: "A relationship is not created by first contact.
  It is created by both sides" (§9), "mutual pre-add" (§13, storage §8),
  "Both ends check" (A3). No sentence says what the first step is, and no
  sentence covers ending one ("no channel close", §13, is about the record
  never being a detour, not about refusing to continue).

## The design

Two moneyless steps on the bilateral chain, each co-signed like any step
(the maker's signature on the operation, the other device's countersignature
on the receipt, per-step keys as A20 has them):

**ESTABLISH.** The first step of every relationship, from `h_0`. Its
operation is `CreateRelationship` (tag 11, the variant recovery already uses)
with the marker `establish`, the counterparty's device id, and as its
commitment the relationship's `h_0` over both geneses, so the step binds both
identities although the canonical `h_0` zeroes them. It carries no amount, no
terms, no nonce. Adding a contact is the person's consent to it:

- The device with the lower device id makes the step when its person adds
  the contact. The device with the higher id, when its person adds, records
  the consent and countersigns the step when it reads it from the spool
  (it polls the relationship's spool at `h_0` from the add on). If the higher
  id adds first, nothing travels until the lower id adds and makes the step;
  the higher id then countersigns on its next read. One maker per
  relationship: no two establishments ever cross.
- The relationship is *established* on a device once that device holds the
  countersigned ESTABLISH at `h_1`. Until then it is *opened* (leaf at
  `h_0`, no step) or, on the maker, *proposed*.
- A DSM Connect approval (A11) adds the contact on each side through the
  relay, so it goes through the same step. The game's first request waits
  behind the send gate until the step is countersigned.

**TERMINATE.** A step either device may make at any time, from its current
tip on the relationship: from `h_1` or later on an established one, or from
`h_0` on one it opened whose contact never added back. (Built: the maker of
an establishment still in flight holds one step in flight already, and one
step at a time is the rule, so it ends that relationship on its own record
with no second step; nothing moves on it either way.) Its operation is `RemoveRelationship` (tag 12, today refused as a
legacy operation with no producer; it gets its producer). On the maker's
device the relationship is *ending* the moment the step is made: nothing may
be sent or taken on it from then on, whether or not the other side ever comes
back online. The other device, if it holds the contact, countersigns the step
when it reads it: it is being told, not asked, and its countersignature is
the acknowledgement that puts the ending on both chains; the relationship is
then *ended* on both. Two terminations that cross settle as any crossing
steps do (both settle, owner 2026-10-29); the relationship ends either way.

**Refusing before it is established.** A device that has not added the
other has no contact row, reads no spool and sees no proposal: declining is
not adding. The ESTABLISH is the only step that waits for the other side.

**Re-establishing.** Not built: a termination is final. (The note first
proposed a new ESTABLISH from the ended tip; an establishment crossing a
termination would leave the two chains in different lifecycles, and the
owner asked for no re-opening.)

### Where each rule lives

- **Core (`dsm`).** The relationship leaf's tip cache (`RelChainTip`) gains
  a `lifecycle`: Opened, Established, Ending, Ended. `DeviceState::advance`
  refuses, as conservation does, a value-bearing operation on a relationship
  that is not Established; an ESTABLISH on one that is not Opened or Ended;
  a TERMINATE on one that is not Established or Opened. `refuse_zero_effect`
  admits `RemoveRelationship` and the `establish` `CreateRelationship` (they
  change state: A21). The classifier already gives both no economic effect.
  `ValueCapability` is untouched (it is recovery's measure).
- **Sender (SDK).** `handlers/relationship_status.rs` is already the one
  authority on whether a send may go. It gains the block reasons
  `NotEstablished` ("waiting for them to add you"), `Ending` and `Ended`.
  Every send path already consults it (wallet.send, Bluetooth prepare,
  Connect payment). The contacts add route makes or consents to the
  ESTABLISH; a new `contacts.terminate` route makes the TERMINATE.
- **Receiver (SDK).** The spool read recognises three kinds of copy on a
  relationship: a Transfer (as today), an ESTABLISH, a TERMINATE. The two
  new kinds take the same recognition (sender is a contact, SIG A, addressed
  to this device, parent is the pinned head of the sender) and then their own
  apply: no terms, no nonce, no economic admission, no debit to locate. The
  apply id is the step's commitment. Countersign and finality travel as they
  do for a Transfer. A Transfer on a relationship that is not established is
  refused by core at apply, and the copy is passed over with that reason.
- **Client schema.** `contacts` gains `relationship_state` (opened,
  proposed, established, ending, ended) and `established_tip`. Beta does not
  migrate: the schema version moves from 44 to 45 and the app database is
  wiped on the phones and the simulator.
- **Proto.** `RelationshipSendBlockReason` gains NOT_ESTABLISHED, ENDING,
  ENDED; `ContactAddResponse` and the contact list carry
  `relationship_state`; a `ContactTerminateRequest`/`Response` pair.
- **Wallet UI (both looks, display only).** A contact shows one of: Waiting
  for them to add you, Established, Ending, Ended. Send is offered only when
  established. A contact page offers End relationship; an ended one offers
  Add again. The Connect approval screen is unchanged.
- **Spec.** Amendment A33 in the explainer under §19, in the owner's words
  above; §9, §13 and A3 keep their sentences and gain the step's name;
  MASTER_REQUIREMENTS rows for the two steps and the gate; CONFORMANCE_GAPS,
  VERIFICATION_MATRIX rows naming the tests; the spec pins re-hashed.
- **TLA+.** `DSM.tla`: `CreateRelationship` becomes `Establish`, a step
  from tip 0 enabled only when both devices hold the contact; `Send` is
  enabled only once established; a `Terminate` action; an invariant that no
  value step is ever applied on a relationship that is not established. A
  falsification config that drops the establishment guard and violates
  exactly that invariant. `DSM_BilateralLiveness`: establishment settles.
  Registry count and `exhaustive_by_construction` updated.
- **Lean.** A theorem in `DSMStepTransition.lean` that a lifecycle fold
  admits a value step only from Established, with its claim-trace row.
- **Tests.** The frozen hash vectors (`smt_tripwire_vectors.rs`) pin hash
  functions, none of which change; the "first write" fixture becomes the
  ESTABLISH step's fold and is re-pinned with that note. SDK two-device
  tests: adding on both sides completes the step before any send (the
  harness runs the poll each device's background poller runs). New tests:
  a send before the other side adds is refused with NotEstablished and
  nothing leaves the device; a copy sent to a device that did not add is
  never read; a terminated relationship refuses sends both ways and takes no
  transfer; re-establish after an ending; crossing terminations settle; the
  A14 tests keep their names and pass.

### Out of this change

Bluetooth pairing's own session (A27) and unpair stay as they are: unpair
forgets a radio address, it does not end a relationship. Offline steps run
only on established relationships, which they already require in practice
(a pairing needs the contact on both sides).
