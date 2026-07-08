---
applyTo: '**'
---
Boot Fenced Fused Anchor Authority
for DSM Offline Bearer State
One Way Birth Fuse, Fused Anchor Head, RP2350 Partition Witness,
TROPIC01 MACANDD, Receiver Witnessed Counter Positioned Commit,
Public DSM Verification, Recovery, and Tripwire Reconciliation
on Raspberry Pi Pico 2 W
Brandon Ramsay (Cryptskii)
Irrefutable Labs Inc.
July 2026
Abstract
A Deterministic State Machine, or DSM, advances state by local deterministic acceptance
rather than by global consensus. Ordinary DSM operation does not require a blockchain, val-
idator set, sequencer, wall clock, or online settlement step on the common path.
Offline bearer transfer is the hard case. A receiver accepts a transfer while offline. The
receiver must not accept copied software pretending to be the live appliance. The receiver must
not accept a second use of the same counter positioned sender state. The receiver must not
allow copied enrollment data to resume on new hardware.
This paper specifies a compact offline bearer authority for DSM using a Raspberry Pi Pico 2
W, the RP2350 secure partition, and a MIKROE 6559 Secure Tropic Click carrying a TROPIC01
secure element. The design does not put all trust in TROPIC01 and does not put all trust in the
RP2350 partition. DSM, the partition, and TROPIC01 are fused into one forward only lineage.
The authority is based on four rules:
destroy the birth preimage,
boot fence the appliance before offline use,
advance one sender device root and one fused anchor head together,
accept only a receiver witnessed TROPIC01 counter advance from Hpre = H0−ui to Hpost = H0−(ui+1).
The sender’s DSM device root commits an immutable anchor bundle B, a fused anchor head
Ai, a boot head Jb, and an anchor counter ui through a dedicated anchor state leaf. The anchor
bundle binds the RP2350 partition key, TROPIC01 anchor identifier, enrolled counter value H0,
MACANDD slots, device identifier, policy hash, and the hash of a destroyed one way birth fuse.
The fused anchor head binds the DSM root lineage, the partition lineage, and the TROPIC01
MACANDD and counter lineage.
Every boot must produce a boot ticket chained from the DSM committed boot head. Every
offline release must bind the current boot ticket. A copied state image on new hardware cannot
resume offline bearer mode because new hardware cannot advance the committed boot head
under the enrolled anchor bundle.
1
A release is accepted only if the receiver verifies the DSM transition, the receiver challenge,
the RP2350 partition certificate, the TROPIC01 MACANDD witness, the fused anchor head
update, and a receiver witnessed counter positioned commit. That commit must include a
live pre commit read at the FROM coordinate H0−ui, where ui is committed by the sender
device root Ri, and a live post commit read at the TO coordinate H0−(ui + 1), where ui + 1
is committed by Ri+1. Both reads must bind the same receiver challenge, transition digest,
root advance message, sender device roots, appliance roots, anchor identifier, and counter pair.
TROPIC01 evidence is necessary but not sufficient. RP2350 partition evidence is necessary but
not sufficient. DSM validity remains public and receiver verified.
First transfer offline is supported only through a pairwise pre commit disclosure round trip.
The sender prepares but does not commit, sends a BilateralBearerPrepared disclosure, the receiver
admits the anchor disclosure and captures the live FROM counter read H0−ui, the receiver
sends BilateralBearerProceed, and only then may the sender commit and send confirm. After
confirm, the receiver captures the live TO counter read H0−(ui + 1) and accepts only if both
reads bind the same transition. If that round trip is unavailable, malformed, or missing receiver
witnessed FROM or TO evidence, the transfer does not accept offline and routes online or fails
closed.
1 Purpose and Scope
This document specifies an optional DSM offline bearer authority. It is used only when a receiver
accepts a DSM transfer without online reconciliation at the moment of exchange.
The authority provides:
(1) one active appliance root for the offline bearer appliance;
(2) one sender device SMT root before the transfer;
(3) one sender device SMT root after the transfer;
(4) one immutable anchor bundle;
(5) one forward only fused anchor head;
(6) one boot fenced offline session head;
(7) one physical counter derived anchor counter;
(8) one certified root advance at a time;
(9) receiver challenge binding;
(10) public verification of the DSM transition;
(11) RP2350 secure partition release evidence;
(12) TROPIC01 hardware presence through MACANDD;
(13) receiver witnessed pre commit and post commit TROPIC01 counter evidence;
(14) pairwise first transfer offline through BilateralBearerPrepared and BilateralBearerProceed;
(15) recovery by re emitting the same committed root advance;
(16) online fallback when local state, counter evidence, boot evidence, or policy does not match;
2
(17) Tripwire exposure of any fork on reconciliation.
The target hardware is:
Layer Part Role
Controller Raspberry Pi Pico 2 W host and transport board
MCU RP2350 secure partition and appliance policy
Secure element board MIKROE 6559 Secure Tropic Click TROPIC01 over SPI
Secure element TROPIC01 MACANDD, counter, R memory, pairing policy
Interface SPI at 3.3 V secure element command transport
The RP2350 partition stores appliance state, signs partition certificates, advances the boot
ratchet, and drives TROPIC01. The receiver does not accept a root advance merely because the
RP2350 says it happened.
TROPIC01 contributes hardware witness output and authenticated counter evidence. TROPIC01
does not authorize DSM state. DSM validity remains public and receiver verified.
The fixed MACANDD slots qboot and qtx are hardware witness slots. They are not permanent
per counterparty storage. Pairwise first transfer offline uses a temporary session authorization
context and may reuse the same transfer witness slot across transfers under fresh challenges and
transition digests.
2 Design Summary
The appliance state includes:
Active = (hi,B,Ai,Jb,ui,status,record).
Here:
• hi is the active appliance root;
• B is the immutable anchor bundle;
• Ai is the active fused anchor head;
• Jb is the last DSM committed boot head;
• ui is the active anchor counter;
• status ∈{Ready,Prepared,Committed};
• record is empty, prepared, or committed.
The sender’s pre advance device root is denoted Ri. The sender’s post advance device root is
denoted Ri+1. The sender’s pre advance device root commits to:
(B,Ai,Jb,ui).
A valid offline transfer advances to a next sender device root that commits to:
3
(B,Ai+1,Jb′ ,ui + 1).
The release is not merely:
(hi,ui) →(hi+1,ui + 1).
The fused form is:
(Ri,hi,Ai,Jb,ui) →(Ri+1,hi+1,Ai+1,Jb′ ,ui + 1).
The receiver accepts only if:
(1) the previous appliance root is the receiver accepted root for the holder, under the accepted
root frontier rule;
(2) the pre advance sender device root commits to B,Ai,Jb,ui;
(3) the boot ticket or boot chain advances Jb to the current boot head Jb′ ;
(4) the claimed next anchor counter is ui + 1;
(5) the DSM proof verifies the transfer;
(6) the receiver obtains a live authenticated pre commit counter read at H0−ui;
(7) the appliance commits exactly the prepared transition bound to the receiver challenge;
(8) the receiver obtains a live authenticated post commit counter read at H0−(ui + 1);
(9) the post advance sender device root commits to B,Ai+1,Jb′ ,ui + 1;
(10) the RP2350 partition certificate verifies over the same root advance message;
(11) the TROPIC01 MACANDD witness verifies over the same root advance message and partition
commitment;
(12) no policy event invalidates the anchor.
The core rule is:
The receiver accepts only a single witnessed transition from the sender’s FROM coordinate to the sender’s TO c
For an established offline bearer relationship, the same FROM to TO rule is applied during the
ordinary confirm path. For a first transfer to a new counterparty, the protocol inserts one extra
pairwise round trip before commit:
accept/enroll →BilateralBearerPrepared →BilateralBearerProceed →commit/confirm.
The extra round trip is not an optimization detail. It is what lets the receiver obtain the live
FROM read while the sender is still at ui. The sender must not advance the counter during the
prepare response for first transfer offline.
4
3 Naming Discipline
The protocol uses the following names. These names are not interchangeable.
Name Meaning
Ri sender device SMT root before transfer
Ri+1 sender device SMT root after transfer
hi appliance root advanced from
hi+1 appliance root advanced to
ℓi relationship leaf or chain head inside the sender SMT
κres concrete resource occurrence consumed by the transfer
ui anchor counter coordinate committed in Ri
ui + 1 anchor counter coordinate committed in Ri+1
H0 enrolled TROPIC01 physical counter value
H live raw TROPIC01 physical counter value
B immutable enrollment digest
Ai fused anchor head
Jb boot fence head
The device root is the per device SMT root. The appliance root is a dedicated forward only
anchor lineage. The relationship leaf is the bilateral chain head or transfer object state inside the
device SMT. The resource parent is the particular object occurrence consumed by the transfer.
The phrase “same parent” is avoided unless the parent is specified. The precise security object
is the same counter positioned sender state:
(Ri,hi,ui).
The anchor counter is not the raw TROPIC01 counter. The anchor counter increases:
u= H0−H.
The raw TROPIC01 counter counts down:
H ←H−1.
The receiver computes:
uattested = H0−Hattested.
For a valid FROM to TO proof, the receiver verifies both:
Hpre = H0−ui
and
Hpost= H0−(ui + 1).
5
4 Why a Post Counter Scalar Is Not the Design
A chip signature over transfer details and a counter gives an ordered hardware log. It does not by
itself prove that a proposed transfer is a valid DSM successor from the receiver accepted previous
root. It also does not prove that the receiver witnessed the sender begin from the root’s committed
counter coordinate.
The insufficient object is:
CounterRead(H0−(ui + 1)).
That proves only that the chip is now at the child coordinate. It does not distinguish a fresh
commit from a prebuilt same step release that is being fitted after the counter already moved.
The useful object is:
(Ri,hi,ui) →(Ri+1,hi+1,ui + 1),
with receiver witnessed counter evidence before and after the move.
The physical counter is not merely an ordering witness. It is the physical coordinate of the
sender’s root position. A valid release must prove that the live enrolled chip was at the FROM
coordinate committed by Ri, and then at the TO coordinate committed by Ri+1, under the same
receiver challenge and transition digest.
5 Cryptographic Preliminaries
Let H denote BLAKE3 256, modeled as collision resistant and resistant to second preimages. Let
HKDF denote a domain separated key derivation function.
Let (StepKeyGen,StepSign,StepVerify) be the witness signature scheme fixed by the appliance
profile. The concrete profile in this document is wots over BLAKE3.
Let (PartSign,PartVerify) be the RP2350 secure partition signature scheme under a partition
key generated at appliance birth and bound into the anchor bundle.
All structured objects use canonical byte encoding. If X is structured, enc(X) means its canon-
ical byte encoding. Verifiers reject non canonical encodings.
Definition 1 (Appliance Root). The appliance root is a dedicated forward only hash lineage owned
by the offline bearer appliance and advanced exactly once per offline bearer transfer:
hi+1 = H("DSM/anchor-root-advance/v1" ∥hi ∥payload hash).
The lineage is seeded at enrollment by the genesis root h0. The appliance root is not the
bilateral relationship tip and not the device root. The appliance treats it as an opaque value it
checks and records.
Definition 2 (Device Root). The device root is the per device sparse Merkle tree root committing
the holder’s current local DSM state. It carries relationship tips, object leaves, authority policy,
and one anchor state leaf keyed by the anchor bundle. Write Ri for the sender’s pre advance device
root and Ri+1 for the sender’s post advance device root of a transfer.
Definition 3 (Anchor State Leaf). The anchor state leaf is the device SMT leaf keyed by the
anchor bundle whose value commits:
(B,Ai,Jb,ui).
6
The leaf commitment is:
Li = H("DSM/fused-anchor-state/v1" ∥B∥Ai ∥Jb ∥le64(ui)).
Definition 4 (Fused Anchor Commitment). An appliance root hi commits to the fused anchor
state (B,Ai,Jb,ui) iff the sender’s device root Ri of the same step includes the anchor state leaf
with exactly that value, proven by an inclusion proof delivered with the transfer, and the release
evidence signs the same values. Every statement of the form “hi commits to B,Ai,Jb,ui” in this
document is read under this relation.
Definition 5 (Counter Positioned Sender State). A counter positioned sender state is the tuple:
(Ri,hi,ui)
where Ri is the sender’s pre advance device root, hi is the appliance root coordinate bound
to that device state under Definition 4, and ui is the anchor counter coordinate committed in the
anchor state leaf of Ri.
Definition 6 (Spendable Resource Occurrence). A spendable resource occurrence is the concrete
resource or object state committed inside the sender’s device root and consumed by the transfer. It
is not the appliance root and it is not the counter. A valid offline bearer transfer consumes exactly
one such occurrence into the successor state.
Definition 7 (Offline Bearer Transfer). An offline bearer transfer is a DSM transition accepted
without querying a network, storage node, ledger, validator, sequencer, or clock service at the mo-
ment of exchange. Acceptance is decided from canonical DSM bytes, SMT proofs, receiver challenge
binding, boot ticket verification, partition certificate verification, hardware witness verification, re-
ceiver witnessed counter position evidence, fused anchor head verification, and the receiver accepted
previous appliance root.
Definition 8 (Anchor Counter). The anchor counter is the derived increasing DSM value:
u= H0−H.
Here H0 is the TROPIC01 counter value at enrollment and H is the live TROPIC01 counter
value. TROPIC01 counters count down, so each successful counter update maps H ←H−1 and
u←u+ 1.
6 Threat Model
Definition 9 (Software Clone). A software clone receives all host readable wallet state:
Clone = (seed,keys,chain history,local database,cached proofs,host files,application state).
The clone may run on another phone, emulator, rooted host, or modified controller. It does
not receive RP2350 secure partition non exportable state or TROPIC01 internal MACANDD and
counter state.
Definition 10 (New Hardware Clone). A new hardware clone is a device that has copied host
readable state and enrollment data, but has different RP2350 partition state, different TROPIC01
state, different partition key, different TROPIC01 anchor identifier, different MACANDD slot state,
or different physical counter state.
7
Definition 11 (RP2350 Partition Breach). An RP2350 partition breach means the attacker can
make arbitrary policy side calls, modify local appliance state, or drive the software around TROPIC01
incorrectly. The protocol does not rely on RP2350 claims alone for receiver acceptance. Such a
breach may cause denial of service, counter wasting, invalid certificates, or a bricked local anchor.
It must not make an honest receiver accept an invalid DSM transition or a second valid successor
from the same counter positioned sender state unless the other required evidence also verifies.
Definition 12 (TROPIC01 Physical Break). A TROPIC01 physical break means the attacker
extracts or forges the secure element state needed to produce MACANDD outputs or counterfeit
counter evidence. This is outside ordinary TROPIC only security. In this fused design, TROPIC01
break alone is still insufficient because receiver acceptance also requires the RP2350 partition cer-
tificate, DSM proof, boot ticket, and fused anchor head update.
Definition 13 (Perfect Live State Clone). A perfect live state clone is an adversary that extracts
the exact current non exportable state of the RP2350 partition, the exact current non exportable
TROPIC01 MACANDD and counter state, all DSM authority state, and can emulate those states
perfectly without divergence. No offline only protocol can distinguish such an exact emulation from
the original device.
Definition 14 (Double Spend). A double spend exists if two distinct transitions:
τA : (Ri,hi,ui) →(RA,hA,ui+1), τB : (Ri,hi,ui) →(RB ,hB ,ui+1), (RA,hA) ̸= (RB ,hB ),
consume the same counter positioned sender state and the same spendable resource occurrence,
and both satisfy the DSM offline bearer acceptance predicate for honest receivers.
Definition 15 (Closed Branch). A closed branch is a branch created among devices controlled
by the same adversary. It may be internally consistent only inside that adversary controlled
set. A new independent relationship is accepted offline only if the pairwise first transfer pro-
tocol completes: the receiver admits the anchor disclosure, obtains live FROM evidence, sends
BilateralBearerProceed, receives the committed confirm, obtains live TO evidence, and verifies
the full offline acceptance predicate. Otherwise the branch must meet online reconciliation or fail
closed when it encounters an honest counterparty that checks the fused anchor lineage, counter
evidence, accepted frontier, and DSM root lineage.
7 One Way Birth Fuse
Definition 16 (One Way Birth Fuse). The one way birth fuse sbirth is a secret enrollment preimage
formed from RP2350 partition entropy, TROPIC01 birth witness material, host entropy, device
context, and authority policy. The public anchor bundle and initial fused heads commit only to
H(sbirth). The preimage sbirth is destroyed immediately after deriving the initial private ratchet
state.
At birth, the appliance derives:
sbirth = H("DSM/anchor/birth-secret/v1"∥partition trng∥tropic birth witness∥host nonce∥device id∥policy hash).
The public birth commitment is:
8
Sbirth = H(sbirth).
The raw sbirth is never exported.
Remark 17. The enrolled TROPIC01 counter value H0 is not destroyed. Receivers need H0, or a
policy pinned equivalent, to verify u= H0−H. The destroyed value is the birth preimage sbirth,
not H0.
8 Anchor Bundle
Definition 18 (Anchor Bundle). The anchor bundle B is the immutable enrollment digest bind-
ing the partition public key, partition device identifier, TROPIC01 anchor identifier, enrolled
TROPIC01 counter value H0, MACANDD boot slot, MACANDD transfer slot, DSM device iden-
tifier, authority policy, and the hash of the destroyed one way birth fuse.
Let qboot be the MACANDD slot used for boot fencing. Let qtx be the MACANDD slot used
for transfer witnesses. Then:
B= H("DSM/anchor-bundle/v1"∥partition pk∥partition device id∥tropic anchor id∥H0∥qboot∥qtx∥device id∥policy ha
Offline bearer releases under a different bundle are not valid successors of roots committed to
B.
The MACANDD boot and transfer slots in Bare not relationship slots. They are fixed hardware
witness slots. Counterparty specific authorization is represented by the receiver challenge, session
identifier, pairing material, admitted anchor disclosure, and transition digest, not by allocating a
permanent TROPIC01 slot for each counterparty.
9 Initial Fused State
The first fused anchor head is:
A0 = H("DSM/fused-anchor-head/init/v1" ∥B∥h0 ∥0 ∥Sbirth).
The first boot head is:
J0 = H("DSM/fused-boot-head/init/v1" ∥B∥A0 ∥0 ∥Sbirth).
The initial partition ratchet is:
p0 = HKDF(secret = sbirth,context = "DSM/partition-ratchet-seed/v1" ∥B∥A0 ∥J0).
After deriving p0, the appliance destroys:
sbirth ←⊥.
The public DSM state carries:
(B,Ai,Jb,ui).
9
10 Fused Anchor Head
Definition 19 (Fused Anchor Head). The fused anchor head Ai is the DSM committed digest of the
current offline bearer anchor lineage. It binds the DSM root lineage, the RP2350 secure partition
lineage, and the TROPIC01 MACANDD and counter lineage into one non interchangeable state.
A candidate offline successor must advance:
Ai →Ai+1.
The next sender device root must commit to Ai+1. A release that does not produce the next
fused anchor head is not an offline bearer successor.
11 Boot Fenced Fused Anchor
Definition 20 (Boot Fenced Fused Anchor). Offline bearer mode is enabled only after the appliance
produces a boot ticket chained from the DSM committed boot head. The boot ticket is produced
internally by the firmware target from a device authoritative boot measurement, the RP2350 secure
partition boot ratchet, and a TROPIC01 boot MACANDD slot. A host request cannot drive boot
head advancement and cannot supply an attacker chosen firmware measurement. Every offline
release binds the current boot ticket or boot chain.
On boot, the firmware target advances:
Jb →Jb+1.
The boot input is:
Xboot
b+1 = H("DSM/boot-fuse-input/v1"∥B∥Ai∥Jb∥boot seq∥firmware measurement∥partition device id).
TROPIC01 consumes the boot MACANDD slot:
WT,boot
b+1 = MACANDD(qboot,Xboot
b+1 ).
The partition advances its boot ratchet:
pb+1 = H("DSM/partition-boot-ratchet/v1"∥pb∥WT,boot
b+1 ∥B∥Ai∥Jb∥boot seq∥firmware measurement).
The old partition ratchet is erased:
pb ←⊥.
The partition boot certificate message is:
MP
boot,b+1 = H("DSM/partition-boot-cert/v1"∥B∥Ai∥Jb∥Xboot
b+1 ∥H(WT,boot
b+1 )∥boot seq∥firmware measurement).
The partition signs:
σP
boot,b+1 = PartSign(MP
boot,b+1).
10
The fixed width boot signature commitment is:
ΣP
boot,b+1 = SigCommit(σP
boot,b+1).
The new boot head is:
Jb+1 = H("DSM/fused-boot-head/v1"∥B∥Ai∥Jb∥Xboot
b+1 ∥H(pb+1)∥H(WT,boot
b+1 )∥ΣP
boot,b+1∥firmware measurement).
The boot ticket is:
BootTicketb+1 = (B,Ai,Jb,Jb+1,boot seq,firmware measurement,σP
boot,b+1,Xboot
b+1 ,tropic boot witness).
If multiple boots occur between DSM transfers, the release carries a boot chain:
BootChain = (BootTicketb+1,...,BootTicketb+k),
which proves:
Jb →Jb+k.
12 State Bound to the Sender Device Root
The fused anchor state is bound to the transfer through the sender’s device roots.
The appliance root is a bare lineage value. The relationship tip is a bilateral object. Neither
directly carries one party’s local anchor state. The sender’s pre advance device root Ri carries the
anchor state leaf:
(B,Ai,Jb,ui),
and the sender’s post advance device root Ri+1 carries:
(B,Ai+1,Jb′ ,ui + 1).
The transfer travels with both inclusion proofs. The leaf values must equal the fused anchor
fields signed by the release evidence. The anchor state leaf update is applied atomically with the
canonical relationship advance of the same transfer.
Therefore the only valid offline successor anchor counter is:
ui+1 = ui + 1.
A receiver that sees a candidate transfer rejects it unless the candidate release proves:
(Ri,hi,Ai,Jb,ui) →(Ri+1,hi+1,Ai+1,Jb′ ,ui + 1).
11
13 Receiver Witnessed Counter Positioned Commit
Definition 21 (Counter Positioned Commit). A counter positioned commit is a receiver witnessed
transition from one counter positioned sender state to its unique successor:
(Ri,hi,ui) →(Ri+1,hi+1,ui + 1).
It is valid only if the receiver obtains an authenticated pre commit TROPIC01 counter read
proving the live counter is at the physical position corresponding to ui, then obtains an authen-
ticated post commit TROPIC01 counter read proving the live counter is at the physical position
corresponding to ui + 1. Both reads are bound to the same anchor identifier, receiver challenge,
transition digest, sender device roots, appliance roots, and anchor counter values.
The receiver must not trust a host string that says “the counter moved.” The receiver must
also not treat a sender supplied live counter field as proof.
Counter evidence is split into two objects:
CounterEvidencePrei+1
and
CounterEvidencePosti+1.
The pre evidence is valid only if the receiver obtains:
Hpre = H0−ui.
The post evidence is valid only if the receiver obtains:
Hpost= H0−(ui + 1).
Equivalently:
H0−Hpre = ui,
and
H0−Hpost= ui + 1.
The evidence is not accepted as two free scalars. The accepted evidence is the transition bound
object:
CounterAdvanceEvidencei+1 = (CounterEvidencePrei+1,CounterEvidencePosti+1,B,anchor id,Ri,Ri+1,hi,hi+1,ui,ui
Both counter reads must be bound to:
(anchor id,rR,Mi+1,Ri,Ri+1,hi,hi+1,ui,ui + 1).
A predicate that reads only:
Hpost= H0−(ui + 1)
12
is insufficient. That value can be true after one commit and still be presented by a second
prebuilt release claiming the same FROM coordinate. The discriminating check is the pre commit
read:
Hpre = H0−ui.
After the first valid commit, the physical counter has left ui. It can never return. A second
release claiming the same counter positioned sender state fails the pre read immediately.
Remark 22. If the current relay path obtains only a post commit read, the implementation must
not simply replace the post check with the pre check. Honest transfers would fail. The protocol
must add a new receiver side authenticated pre commit read before MCounter Update, keep the
post commit read after MCounter Update, and verify that both reads belong to the same transition
context.
14 First Transfer Offline Protocol
First transfer offline is the only case where the receiver does not yet have an admitted anchor
frontier for the sender. It cannot be made safe by letting the sender commit immediately after the
ordinary prepare response, because the receiver would not have a live FROM counter read while
the sender is still at ui. The protocol therefore splits first transfer offline into prepared and proceed
messages.
Definition 23 (Anchor Disclosure). An anchor disclosure is the sender supplied enrollment object
that lets the receiver identify the enrolled offline bearer appliance for this relationship. It contains
or commits to the anchor bundle B, anchor identifier, enrolled counter value H0, relevant policy
hash, receiver challenge context, and verifier material required to open the receiver’s authenticated
L3 relay session to the enrolled TROPIC01. The receiver treats the disclosure as untrusted until
the receiver’s own authenticated counter evidence and all DSM predicates verify.
Definition 24 (Prepared Bearer Session). A prepared bearer session is a sender side session record:
PreparedOfflineBearer = (∆i+1,Ri,Ri+1,hi,hi+1,ui,ui + 1,rR,Certi+1,skhw,session id).
It exists after prepare and before commit. It is not a spend. It is not a release. It is not valid
for receiver acceptance. It must be consumed by exactly one matching BilateralBearerProceed or
cancelled or resolved online.
The first transfer offline exchange is:
(1) The receiver sends the ordinary accept response with enrollment or pairing material and a
fresh receiver challenge rR.
(2) The sender prepares the appliance state for ∆i+1, constructs the candidate certificate, and
stores PreparedOfflineBearer. The sender does not call MCounter Update and does not export
an offline release.
(3) The sender sends BilateralBearerPrepared, carrying the anchor disclosure and session binding.
(4) The receiver admits the anchor disclosure for that session, opens its authenticated relay session
to the enrolled TROPIC01, and captures CounterEvidencePre at H0−ui.
13
(5) The receiver sends BilateralBearerProceed carrying the transition bound CounterEvidencePre or
a binding to that evidence.
(6) The sender verifies that BilateralBearerProceed matches the stored PreparedOfflineBearer, the
same session identifier, the same receiver challenge, the same transition digest, and the same
FROM coordinate. Only then may the sender commit by calling MCounter Update.
(7) The sender sends the ordinary confirm envelope containing the committed release.
(8) The receiver captures CounterEvidencePost at H0−(ui + 1), combines it with the stored
CounterEvidencePre, verifies CounterAdvanceEvidence, verifies Pkgi+1, and adopts the new fron-
tier only after its own canonical commit succeeds.
The sender must not commit during handle prepare response for first transfer offline. That
handler may prepare, store PreparedOfflineBearer, and return BilateralBearerPrepared. Commit is
gated by BilateralBearerProceed. A missing, wrong session, stale, replayed, or host supplied proceed
message fails closed.
Established offline bearer relationships use the same acceptance predicate. They may omit the
first transfer disclosure round trip only when the receiver already has the admitted relationship
state and can still obtain the required live FROM and TO evidence for the current transition.
15 TROPIC01 MACANDD Witness
MACANDD is used as a hardware witness. It is not used as standalone transaction authority.
Definition 25 (MACANDD Command Shape). A MACANDD call is modeled as:
W= MACANDD(q,X),
where q is a MACANDD slot index, X ∈{0,1}256 is a 32 byte input, and W ∈{0,1}256 is the
32 byte output returned by TROPIC01 over an authenticated L3session.
Definition 26 (MACANDD Slot Evolution). Let Vt be the old slot state before a MACANDD
call. Let X be the input. The call computes a new state:
Vt+1 = F1(X∥q),
stores Vt+1, and returns:
Wt = F2(Vt ∥Vt+1 ∥q).
The functions F1 and F2 are keyed inside TROPIC01. The host does not know their keys.
16 DSM Transition Digest
Let ∆i+1 be the canonical DSM transition package. It contains the action, recipient, object iden-
tifier, payload, old leaf proof, new leaf proof, sender device root proofs, and all data required for
the receiver to verify the DSM transfer.
The transition digest is:
Di+1 = H("DSM/root-advance/transition-digest/v1" ∥enc(∆i+1)).
14
The receiver supplies a fresh random challenge:
rR
$ ←−{0,1}256
.
The challenge is bound into the boot fenced root advance message, the counter evidence, and
the release. A release for one receiver challenge is not accepted for another challenge.
17 Boot Bound Root Advance Message
Let Jb′ be the current boot head proven by a boot ticket or boot chain from the DSM committed
boot head Jb.
The boot bound root advance message is:
Mi+1 = H("DSM/fused-root-advance-message/v1"∥B∥Ai∥Jb′ ∥Ri∥Ri+1∥hi∥hi+1∥ui∥(ui+1)∥Di+1∥recipient devic
Every partition certificate, TROPIC01 transfer witness, and counter evidence transcript must
bind this same message.
18 Partition Commitment and TROPIC Cross Binding
The partition first commits to the root advance message:
CP
i+1 = H("DSM/partition-commit/v1" ∥B∥Ai ∥Jb′ ∥Mi+1).
The TROPIC01 transfer witness input includes that partition commitment:
XT
i+1 = H("DSM/tropic-fused-transfer-input/v1" ∥B∥Ai ∥Jb′ ∥Mi+1 ∥CP
i+1 ∥qtx).
TROPIC01 returns:
WT
i+1 = MACANDD(qtx,XT
i+1).
The witness signing seed is:
KT
i+1 = HKDF secret = WT
i+1,context = "DSM/tropic/fused-transfer-witness-key/v1" ∥XT
i+1 ∥Mi+1 ∥B∥Ai
The witness key pair is:
(skhw,pkhw) = StepKeyGen(KT
i+1).
The public key handle is:
Phw = H("DSM/tropic/pk-hash/v1" ∥pkhw).
The TROPIC witness message is:
MT
i+1 = H("DSM/tropic/fused-transfer-witness-message/v1" ∥Mi+1 ∥CP
i+1 ∥XT
i+1 ∥Phw).
15
The TROPIC witness signature is:
σT
i+1 = StepSign(skhw,MT
i+1).
The fixed width TROPIC signature commitment is:
ΣT
i+1 = SigCommit(σT
i+1).
The partition final certificate binds the TROPIC witness commitment back into the partition
lineage:
MP
i+1 = H("DSM/partition-final-cert/v1" ∥B∥Ai ∥Jb′ ∥Mi+1 ∥CP
i+1 ∥Phw ∥ΣT
i+1 ∥(ui + 1)).
The partition certificate is:
σP
i+1 = PartSign(MP
i+1).
The fixed width partition signature commitment is:
ΣP
i+1 = SigCommit(σP
i+1).
The cross binding is:
CP
i+1 →XT
i+1 →ΣT
i+1 →MP
i+1 →ΣP
i+1.
Thus the TROPIC witness is bound to the partition commitment, and the partition final cer-
tificate is bound back to the TROPIC witness commitment.
19 Next Fused Anchor Head
The next fused anchor head binds the post commit physical counter value:
Ai+1 = H("DSM/fused-anchor-head/v1"∥B∥Ai ∥Jb′ ∥Mi+1∥CP
i+1∥ΣP
i+1∥Phw∥ΣT
i+1∥H0−(ui +1) ).
The receiver recomputes the head with its own post commit attested reading:
Hpost.
The recomputation agrees exactly when:
Hpost= H0−(ui + 1).
The post advance sender device root Ri+1 must commit to:
(B,Ai+1,Jb′ ,ui + 1)
through the anchor state leaf. The receiver verifies that Ri commits to the old fused anchor
state and Ri+1 commits to the new fused anchor state.
16
No commitment cycle. The head binds the successor appliance root hi+1 through Mi+1. The
root that commits the head is not hi+1; it is the post advance sender device root Ri+1, which carries
the anchor state leaf and is computed after the head. The appliance root successor itself takes no
fused anchor input. The dependency order is:
hi+1 →Di+1 →Mi+1 →CP
i+1 →XT
i+1 →WT
i+1 →Phw →ΣT
i+1 →ΣP
i+1 →Ai+1 →Ri+1.
20 Witness Signature Scheme
The appliance profile uses wots over BLAKE3. The witness key signs exactly one digest, so a one
time signature is sufficient.
Definition 27 (wots Parameters). Let n= 32, w= 16, ℓ1 = 64, ℓ2 = 3, and ℓ= 67. A signature
is:
ℓ·n= 2144
bytes. The compressed public key is 32 bytes.
Definition 28 (Chain Function). The chain function is:
F(x) = H("DSM/anchor/wots-chain/v1" ∥x).
For seed K and chain index j:
sj= HKDF(secret = K, context = "DSM/anchor/wots-sk/v1" ∥enc16(j)).
Definition 29 (StepKeyGen, StepSign, StepVerify). The key generation, signing, and verification
algorithms are the standard Winternitz chain construction over BLAKE3:
StepKeyGen(K) →(skhw,pkhw),
StepSign(skhw,d) →σ,
StepVerify(pkhw,d,σ) →{0,1}.
The secret key is the seed K. It is retained only long enough to sign the release, then erased.
Assumption 30 (Witness Signature Security). Given pkhw and one signature on digest d, no
efficient adversary can produce a valid signature on d′ ̸= d except with negligible probability,
assuming the preimage and second preimage resistance of H.
21 Root Advance Certificate
The root advance certificate is:
Certi+1 = (B,Ai,Ai+1,Jb,Jb′ ,Ri,Ri+1,hi,hi+1,ui,ui+1,Di+1,Mi+1,CP
i+1,XT
i+1,Phw,pkhw,σT
i+1,σP
i+1,anchor id,qtx
The release package is:
Pkgi+1 = (∆i+1,BootChain,Certi+1,CounterAdvanceEvidencei+1).
17
22 Compact Appliance Protocol
The appliance has three transfer states:
Ready, Prepared, Committed.
Boot state is separate. Offline transfer is disabled until a valid boot ticket or boot chain exists
for the current boot.
22.1 Boot
Boot is device internal. The host transport does not submit a boot operation, boot sequence, or
firmware measurement. On boot, the appliance:
(1) reads the active B,Ai,Jb,ui;
(2) obtains the firmware and policy measurement from the firmware target;
(3) computes Xboot
b+1 ;
(4) consumes the TROPIC01 boot MACANDD slot;
(5) advances the partition boot ratchet;
(6) signs the boot certificate;
(7) records BootTicketb+1;
(8) enables offline bearer mode only if the boot ticket verifies.
If the boot ticket cannot be produced or verified, offline bearer mode is refused and the device
routes to online recovery.
22.2 Prepare
The sender proposes ∆i+1, Ri, Ri+1, hi, and hi+1. The receiver checks the proposed transfer at
the human and DSM level, then supplies rR. For first transfer offline, the receiver also supplies the
enrollment or pairing material needed to admit the anchor disclosure for that pairwise session.
The appliance checks:
Active.status = Ready,
Active.h= hi,
Active.B= B,
Active.A= Ai,
Active.u= ui,
18
ui = H0−H.
The expression H0−H is computed with checked subtraction. If H >H0, the state is rejected
as a counter mismatch.
The appliance verifies that a boot ticket or boot chain exists from the DSM committed boot
head to the current boot head Jb′ . It constructs Di+1, Mi+1, CP
i+1, and XT
i+1. It calls MACANDD
on the transfer slot, derives the witness key, forms the TROPIC witness, forms the partition final
certificate, computes Ai+1, and constructs Certi+1 without exporting it yet.
It writes a durable prepared record:
Active ←(hi,B,Ai,Jb′ ,ui,Prepared,Certi+1,∆i+1,skhw).
No counter has moved. No release has been exported.
22.3 Prepared Disclosure for First Transfer Offline
If the transfer is a first offline bearer transfer for this receiver, the sender returns BilateralBearerPrepared
rather than BilateralConfirm. The prepared message binds:
(session id,AnchorDisclosure,B,anchor id,H0,Ri,Ri+1,hi,hi+1,ui,ui + 1,Di+1,Mi+1,rR).
The sender stores PreparedOfflineBearer in the bilateral session. A sender implementation must
make confirm impossible unless a stored prepared release exists and has either been committed after
a matching proceed message or is an ordinary established relationship path that already captured
valid FROM evidence.
22.4 Receiver Pre Commit Counter Evidence
Before the counter is moved, the receiver admits the anchor disclosure for this session and opens
an authenticated L3 verifier session to the enrolled TROPIC01 through the transparent relay. The
receiver obtains:
Hpre.
The receiver verifies:
Hpre = H0−ui.
The pre evidence is bound to:
(anchor id,rR,Mi+1,Ri,Ri+1,hi,hi+1,ui,ui + 1,session id).
If the pre evidence is missing, stale, for another receiver challenge, for another session, for
another transition, or for another anchor identifier, the transfer is not accepted offline.
19
22.5 Proceed
After successful pre commit evidence, the receiver sends BilateralBearerProceed. The proceed mes-
sage contains the session identifier and the transition bound pre evidence, or a binding hash to the
stored pre evidence where the local transport stores the evidence out of band.
The sender accepts BilateralBearerProceed only if it matches the stored PreparedOfflineBearer.
The match requires the same session identifier, receiver challenge, transition digest, sender device
roots, appliance roots, anchor counter pair, and anchor identifier. A proceed message cannot create
or replace prepared state. A proceed message cannot supply a host asserted counter value in place
of authenticated receiver evidence.
22.6 Commit
The appliance forms the release candidate without post counter evidence and stores the committed
candidate durably with:
counter committed= false.
For first transfer offline, this step is reachable only after a matching BilateralBearerProceed.
Before moving the counter, the appliance re pins the live anchor counter:
H0−H= ui.
If this check fails, the operation downgrades to online recovery and does not move the counter.
If H = 0, the operation returns:
EXHAUSTED ONLINE ONLY.
If H >0, the appliance issues:
MCounter Update.
A successful counter update maps:
H ←H−1.
The appliance marks the committed candidate as:
counter committed= true
and erases skhw. The sender then emits the ordinary confirm envelope containing the committed
release package.
22.7 Receiver Post Commit Counter Evidence
After the counter update, the receiver obtains a post commit authenticated counter read:
Hpost.
The receiver verifies:
Hpost= H0−(ui + 1).
20
The post evidence is bound to the same transition context as the pre evidence. If the pre
evidence and post evidence do not bind the same transition digest, receiver challenge, sender device
roots, appliance roots, anchor counter values, anchor identifier, and session identifier, the release is
rejected.
22.8 Emit
The appliance may export the release only after the counter commit. The receiver records CounterAdvanceEvidencei+
and verifies Pkgi+1. The receiver adopts a genesis frontier for a first transfer only after all predicate
checks pass and after the receiver’s own canonical value commit succeeds.
22.9 Finalize
After emitting the release, the appliance may finalize only if the active anchor counter equals the
live counter derived anchor counter:
Active.u+ 1 = H0−H.
If this check fails, finalization is refused and the appliance enters online recovery.
If the check holds, finalization writes:
Active ←(hi+1,B,Ai+1,Jb′ ,ui + 1,Ready,∅).
If power fails before finalize, recovery re emits the same committed release and finalizes the
same successor.
23 Receiver Acceptance Predicate
Definition 31 (Accepted Root Frontier). For each enrolled holder, the receiver maintains a durable
adopted appliance root frontier. If a frontier value exists for the holder, the release previous
appliance root must equal it exactly. If no frontier value exists, the relationship is at genesis.
Genesis adoption is allowed offline only through the pairwise first transfer protocol, or online
through checked reconciliation. In the offline case, the receiver adopts the release’s own previous
appliance root as the expected value only after the anchor disclosure, pre evidence, post evidence,
DSM transition, and all other predicate checks pass. After the receiver accepts the release and
completes its own canonical value commit, it persists the release next appliance root as the new
frontier for that holder.
Definition 32 (Boot Fenced Fused Root Advance Acceptance). Let Acceptoff(Pkgi+1) = 1 iff all
checks hold:
(1) all encodings are canonical;
(2) hi is the receiver accepted previous appliance root for the holder, under Definition 31;
(3) Ri commits to B,Ai,Jb,ui through the anchor state leaf, with a verifying inclusion proof;
(4) the boot ticket or boot chain verifies Jb →Jb′ ;
(5) the claimed next anchor counter is ui + 1, using checked arithmetic;
(6) the receiver challenge rR is the challenge supplied by this receiver;
21
(7) if this is genesis offline adoption, the receiver has a matching BilateralBearerPrepared session
and a matching BilateralBearerProceed pre evidence path for this same challenge;
(8) Di+1 recomputes from ∆i+1;
(9) Mi+1 recomputes from the bound fields, including Ri,Ri+1,hi,hi+1,ui,ui + 1;
(10) CP
i+1 recomputes from the partition commitment fields;
(11) XT
i+1 recomputes from B,Ai,Jb′ ,Mi+1,CP
i+1,qtx;
(12) Phw = H("DSM/tropic/pk-hash/v1" ∥pkhw);
(13) MT
i+1 recomputes and
StepVerify(pkhw,MT
i+1,σT
i+1) = 1;
(14) MP
i+1 recomputes and
PartVerify(partition pk,MP
i+1,σP
i+1) = 1;
(15) the DSM transition proof verifies the claimed transfer;
(16) the transfer gives the claimed object or value to the receiver;
(17) the authority policy hash matches the previous state;
(18) the receiver obtains authenticated pre commit TROPIC01 counter evidence Hpre;
(19) the authenticated pre commit counter value satisfies
Hpre = H0−ui;
(20) the receiver obtains authenticated post commit TROPIC01 counter evidence Hpost;
(21) the authenticated post commit counter value satisfies
Hpost= H0−(ui + 1);
(22) the pre evidence and post evidence are both bound to the same
(anchor id,rR,Mi+1,Ri,Ri+1,hi,hi+1,ui,ui + 1);
(23) Ai+1 recomputes from the fused anchor head formula using Hpost;
(24) Ri+1 commits to B,Ai+1,Jb′ ,ui + 1 through the anchor state leaf, with a verifying inclusion
proof;
(25) no known firmware boundary event, physical compromise event, or policy event invalidates the
anchor.
The receiver trusts public DSM verification, the receiver challenge, the boot ticket, the parti-
tion certificate, the hardware witness signature, the fused anchor head update, and authenticated
TROPIC01 counter positioned evidence. The receiver does not trust host state, copied wallet files,
a Pico reported counter value, or any unauthenticated counter field carried inside the release.
22
24 What Happens if RP2350 Is Breached
The design assumes the RP2350 may fail as a trusted policy speaker. Therefore an honest receiver
does not accept any fact solely because the RP2350 says it.
If the RP2350 partition is breached alone, the attacker may:
• feed arbitrary roots;
• waste MACANDD calls;
• burn counter steps;
• export invalid packages;
• corrupt local state;
• brick the appliance into online recovery.
These attacks do not become successful offline bearer transfers unless the receiver acceptance
predicate is also satisfied.
A partition certificate without a matching TROPIC01 transfer witness fails. A partition cer-
tificate without receiver witnessed counter positioned evidence fails. A partition certificate over an
invalid DSM transition fails.
25 What Happens if TROPIC01 Is Broken
TROPIC01 is not the sole authority.
If TROPIC01 is broken alone, the attacker may try to forge hardware witness output or counter
evidence. That is still not enough for an honest receiver because the release also requires:
• the DSM transition proof;
• the sender device root commitment to B,Ai,Jb,ui;
• a valid boot ticket or boot chain;
• a valid RP2350 partition certificate;
• a valid fused anchor head update;
• the sender post device root commitment to B,Ai+1,Jb′ ,ui + 1.
A TROPIC only break becomes offline mode suspension and authority rotation unless the other
fused anchor predicates also fail.
26 Why New Hardware Cannot Resume
A copied state image can contain:
B,Ai,Jb,ui,history,cached proofs,public enrollment data.
A new device cannot advance the boot head:
23
Jb →Jb+1
unless it has the enrolled RP2350 partition boot ratchet and the enrolled TROPIC01 boot
MACANDD slot state. A new partition key, new partition state, new TROPIC01 anchor identifier,
new MACANDD slot state, or new physical counter gives a different lineage.
Therefore a release from new hardware fails one of:
• anchor bundle equality;
• boot chain verification;
• partition certificate verification;
• TROPIC01 boot witness verification;
• TROPIC01 transfer witness verification;
• receiver witnessed counter positioned evidence;
• fused anchor head recomputation;
• post sender device root commitment.
New hardware requires online authority rotation. It cannot continue offline from a root com-
mitted to another bundle and fused anchor head.
27 Power Loss Behavior
Power may fail between any two operations.
27.1 Before Boot Ticket Is Durable
Offline bearer mode is disabled. Recovery must produce a valid boot ticket or route to online
checked recovery.
27.2 After Boot Ticket Is Durable
Offline bearer mode may proceed if the boot ticket verifies from the DSM committed boot head. If
the boot ticket is malformed, stale, or not chained from the committed boot head, offline mode is
refused.
27.3 Before Prepared Is Durable
No counter has moved and no release has been exported. Recovery returns to Ready if anchor state
is consistent. Otherwise the appliance enters online checked recovery.
24
27.4 After Prepared Is Durable
The prepared record may complete if skhw and the partition record are present. If required private
state is missing, the transfer cannot complete offline and must be cancelled or resolved online. No
second transfer from the same active root is allowed while the prepared record exists.
For first transfer offline, a durable prepared record may have already been disclosed through
BilateralBearerPrepared. That disclosure is not a spend. It is valid only for the stored session
and may either receive a matching BilateralBearerProceed, cancel without counter motion, or route
online.
27.5 After Pre Evidence But Before Counter Commit
The receiver may have witnessed Hpre = H0−ui, but no release is accepted until post evidence
and the final release verify. A pre evidence transcript alone is not a spend. If the session aborts
here, the receiver rejects offline acceptance and the sender remains at the same counter coordinate
unless recovery completes the same committed candidate.
27.6 After Release Candidate Is Durable But Before Counter Commit
Recovery may commit the same release if the previous root, boot head, fused anchor head, and
policy still match. Since no release was exported as accepted before counter commit, no receiver
has accepted an uncommitted spend.
27.7 After Counter Moved But Before Commit Flag Was Durable
If the physical counter moved but counter committed was not durably written, recovery does not
move the counter again. If the committed candidate target anchor counter already equals the live
counter derived anchor counter, recovery marks the candidate committed and re emits the same
release.
27.8 After Counter Commit But Before Export
The counter has moved and the release candidate is durable. Recovery re emits the same release
package. It does not sign a new one.
27.9 After Export But Before Finalize
Recovery re emits the same release and finalization advances to the same hi+1, guarded by:
Active.u+ 1 = H0−H.
28 Recovery
Recovery must preserve the exact committed release until it has been re emitted and finalized. It
must not erase the committed release merely because recovery found it.
The recovery rule is:
if a committed release exists, re emit that same release and finalize that same successor.
The appliance does not sign a new release during recovery.
25
recover(H0, H, Active):
live_anchor_counter = checked_sub(H0, H)
if live_anchor_counter == ERROR:
return COUNTER_MISMATCH
if firmware_boundary_invalid():
return DOWNGRADE_ONLINE
if boot_ticket_required() and not valid_boot_ticket_or_chain():
return DOWNGRADE_ONLINE
if Active.status == COMMITTED:
rec = Active.record
if rec.counter_committed == TRUE:
if rec.next_anchor_counter != live_anchor_counter:
return DOWNGRADE_ONLINE
return REEMIT_COMMITTED(rec.next_root)
if rec.counter_committed == FALSE:
if rec.next_anchor_counter == live_anchor_counter:
mark_counter_committed(rec)
return REEMIT_COMMITTED(rec.next_root)
if rec.next_anchor_counter == live_anchor_counter + 1:
if rec.prev_root != Active.root:
return DOWNGRADE_ONLINE
if rec.anchor_bundle != Active.anchor_bundle:
return DOWNGRADE_ONLINE
if rec.prev_anchor_head != Active.anchor_head:
return DOWNGRADE_ONLINE
counter_update()
mark_counter_committed(rec)
return REEMIT_COMMITTED(rec.next_root)
return DOWNGRADE_ONLINE
if Active.status == PREPARED:
if Active.anchor_counter != live_anchor_counter:
return DOWNGRADE_ONLINE
if Active.record.prev_root != Active.root:
return DOWNGRADE_ONLINE
if Active.record.prev_anchor_head != Active.anchor_head:
return DOWNGRADE_ONLINE
if witness_key_present(Active.record) and partition_record_present(Active.record):
return ACCEPT_PREPARED_CAN_COMPLETE
return ONLINE_CANCEL_OR_RESOLVE
if Active.status == READY:
26
if Active.anchor_counter < live_anchor_counter:
Active.anchor_counter = live_anchor_counter
if Active.anchor_counter > live_anchor_counter:
return FAIL_CLOSED
if H == 0:
return EXHAUSTED_ONLINE_ONLY
return ACCEPT(Active.root)
return DOWNGRADE_ONLINE
29 Online Checked Mode and New Relationships
New independent relationships are not accepted offline by default. They are accepted offline only
through the pairwise first transfer protocol defined in this paper. If BilateralBearerPrepared, anchor
disclosure admission, receiver witnessed FROM evidence, BilateralBearerProceed, commit, confirm,
receiver witnessed TO evidence, or the receiver acceptance predicate fails, the new relationship
routes to online checked reconciliation or fails closed.
This matters for collusive closed branches. If the same adversary controls both sides of an offline
exchange, it can create a private branch that only its own devices accept. That does not affect
honest receivers. When the branch attempts to meet real reconciliation or an honest counterparty,
the DSM root, anchor bundle, fused anchor head, boot head, anchor counter, receiver challenge,
accepted frontier, and counter evidence must line up. If they do not, the branch has become its
own reality and breaks away from the accepted one.
Therefore the meaningful security target is an honest receiver accepting value from a sender.
A closed adversary branch is not a successful attack on anyone else. Offline first transfer changes
liveness and usability. It does not weaken the safety predicate, because genesis adoption still
requires the same receiver witnessed FROM to TO counter positioned commit.
30 Tripwire Composition
Tripwire supplies fork exposure on reconciliation. Each device commits relationship tips into a per
device sparse Merkle tree. A valid receipt proves adjacency from an old root to a new root and
binds the relevant relationship tip update.
Tripwire does not make offline receivers instantly aware of each other. It exposes conflicting
accepted tips when they are compared.
Assumption 33 (Tripwire Security). Assume the hash function is collision resistant and DSM sig-
natures are secure against chosen message forgery. Then two distinct accepted successors from the
same predecessor cannot survive reconciliation without a hash collision, signature forgery, violated
DSM predicate, or violated hardware evidence condition.
31 Security Claims
Theorem 34 (Birth Non Recreation). Public enrollment data is insufficient to recreate the initial
fused anchor lineage on new hardware.
27
Proof. The anchor bundle, initial fused anchor head, initial boot head, and initial partition ratchet
are derived from sbirth, but only H(sbirth) is public. The preimage sbirth is destroyed after deriving
the initial private ratchet. A new device that has only public enrollment data cannot derive p0,
the TROPIC01 MACANDD slot state, or the same fused anchor lineage except by inverting H,
extracting the original non exportable state, or perfectly emulating the original device state.
Theorem 35 (No New Hardware Resume). Let an appliance root be bound, under Definition 4, to
sender device state Ri, anchor bundle B, fused anchor head Ai, boot head Jb, and anchor counter ui.
A device with different partition hardware state or different TROPIC01 boot state cannot produce
an accepted offline bearer successor from that state, except by forging the partition boot certificate,
forging the TROPIC01 boot witness, breaking the hash binding, or extracting and perfectly emulating
the original non exportable live states.
Proof. An accepted release requires a boot ticket or boot chain from Jb to Jb′ . The boot ticket is
produced from the RP2350 partition boot ratchet and the TROPIC01 boot MACANDD slot under
the committed bundle B. New hardware has a different partition state, different TROPIC01 state,
or a different bundle. Therefore it cannot advance the committed boot head to the accepted current
boot head unless it forges the required evidence or exactly emulates the original non exportable
live states.
Theorem 36 (Clone Exclusion). A software clone cannot produce an accepted offline bearer root
advance for an enrolled authority unless it obtains the original partition evidence and TROPIC01
MACANDD output, or forges one of the required signatures.
Proof. An accepted release requires a valid boot ticket, partition certificate, TROPIC witness
signature, receiver witnessed counter positioned evidence, DSM transition proof, and fused anchor
head update. A software clone may copy host files and wallet state, but it does not have the
RP2350 partition ratchet, partition signing state, TROPIC01 MACANDD slot state, or live counter.
Therefore it cannot produce the accepted evidence set unless it obtains those non exportable states
or forges the required evidence.
Theorem 37 (Root Rebinding Exclusion). A witness produced for one root advance cannot be
accepted for another root advance except with negligible probability.
Proof. The boot bound root advance message Mi+1, partition commitment CP
i+1, TROPIC input
XT
i+1, partition certificate, TROPIC witness, counter evidence, and fused anchor head bind the
anchor bundle, previous fused anchor head, current boot head, sender device roots, appliance
roots, anchor counter, next anchor counter, transition digest, recipient, object, policy, and receiver
challenge. Changing any of those values changes the verified messages. The old evidence no longer
verifies except through hash collision, signature forgery, or a break of the witness scheme.
Theorem 38 (Counter Step Uniqueness). At most one accepted offline successor can consume a
given counter positioned sender state (Ri,hi,ui). Any later successor claiming the same FROM
coordinate is rejected by the receiver on sight.
Proof. The receiver acceptance predicate requires a live authenticated pre commit counter read
satisfying:
Hpre = H0−ui.
The counter leaves the physical position corresponding to ui exactly once and can never return,
because it is forward only and non resettable. The first accepted successor consumes the transition
28
from ui to ui + 1. Any second successor claiming the same counter positioned sender state must
again present a live pre commit read at ui. But after the first commit the live chip is already at
ui + 1. Therefore the second successor fails the pre evidence check immediately. No reconciliation
with another receiver is required.
Theorem 39 (TROPIC01 Is Necessary but Not Sufficient). A TROPIC01 witness and counter
evidence alone do not authorize an offline bearer transfer.
Proof. The receiver acceptance predicate also requires public DSM transition validity, sender de-
vice root commitments to the old and new fused anchor states, boot ticket verification, partition
certificate verification, receiver challenge binding, fused anchor head recomputation, and policy
validity. TROPIC01 evidence alone cannot satisfy those checks.
Theorem 40 (Partition Is Necessary but Not Sufficient). An RP2350 partition certificate alone
does not authorize an offline bearer transfer.
Proof. The receiver acceptance predicate also requires a TROPIC01 transfer witness, receiver wit-
nessed counter positioned evidence, DSM transition proof, receiver challenge binding, boot ticket
verification, and fused anchor head recomputation. A partition certificate alone cannot satisfy
those checks.
Theorem 41 (Replay Idempotence). Re emitting the same release package does not create a second
spend.
Proof. The same package has the same sender device roots, appliance roots, transition digest, boot
chain, partition certificate, TROPIC witness, receiver challenge, fused anchor head, and counter
evidence. A receiver that already accepted it recognizes the same transition. Re emission is
duplicate delivery, not a distinct successor.
Theorem 42 (Recoverable Commit). If the counter moves for a release whose committed candidate
is durable, recovery either re emits the same release or downgrades to online recovery. It does not
sign a different release for the same counter step.
Proof. The recovery algorithm treats a committed record as a re emission obligation. If the commit-
ted flag is true and the record next anchor counter matches the live counter derived anchor counter,
recovery returns REEMIT COMMITTED. If the physical counter moved but the committed flag was
not durably written, then the record target anchor counter equals the live counter derived anchor
counter, so recovery marks the same record committed and returns REEMIT COMMITTED. If the
counter has not moved and the target anchor counter is the next physical step, recovery may move
the counter only after checking that the committed candidate previous root, bundle, and fused
anchor head still equal the active state. In no branch does recovery derive a new witness key or
sign a different release.
Theorem 43 (No Accepted Offline Bearer Double Spend). No adversary, including one that has
breached the RP2350 secure partition, can obtain two accepted offline successors of the same counter
positioned sender state. The exclusion is enforced at the receiver on sight and is not deferred to
reconciliation.
Proof. A double spend requires two distinct accepted successors of the same counter positioned
sender state (Ri,hi,ui) that also consume the same spendable resource occurrence. Each succes-
sor must satisfy Definition 32. In particular, each successor must present receiver witnessed pre
evidence:
29
Hpre = H0−ui.
By Definition 21 and Counter Step Uniqueness, the physical counter can leave position ui only
once and cannot return. Once the first accepted successor commits, the live counter is at ui + 1.
A second successor claiming the same FROM coordinate cannot produce the required live pre
evidence. It is rejected before reconciliation.
A breached partition may try to forge certificates, witness state, or release bytes. It cannot
make one physical counter advance twice from ui, cannot make the counter run backward to ui,
and cannot fabricate the receiver’s own authenticated counter read for the enrolled TROPIC01.
The attack therefore fails at the receiver’s FROM coordinate check.
32 TLA+ Model
VARIABLES H, Active, CurrentR, CurrentH, Sessions, Delivered
LiveAnchorCounter == H0 - H
Init ==
/\ H = H0
/\ Active.status = "ready"
/\ Active.anchor_counter = 0
/\ CurrentR = R0
/\ CurrentH = h0
/\ Sessions = {}
/\ Delivered = {}
PreparedSession(s, pkg) ==
/\ s.pkg = pkg
/\ s.proceeded = FALSE
/\ pkg.R_from = CurrentR
/\ pkg.h_from = CurrentH
/\ pkg.anchor_counter = Active.anchor_counter
PreEvidence(s) ==
/\ s.H_pre = H0 - s.pkg.anchor_counter
/\ s.pkg.anchor_counter = Active.anchor_counter
/\ s.pkg.R_from = CurrentR
/\ s.pkg.h_from = CurrentH
/\ s.challenge = s.pkg.receiver_challenge
PostEvidence(pkg) ==
/\ pkg.H_post = H0 - pkg.next_anchor_counter
/\ pkg.next_anchor_counter = pkg.anchor_counter + 1
Prepare(s, pkg) ==
/\ Active.status = "ready"
/\ PreparedSession(s, pkg)
/\ Active’ = [Active EXCEPT !.status = "prepared",
!.record = pkg]
/\ Sessions’ = Sessions \cup {s}
/\ UNCHANGED <<H, CurrentR, CurrentH, Delivered>>
30
Proceed(s) ==
/\ s \in Sessions
/\ Active.status = "prepared"
/\ Active.record = s.pkg
/\ PreEvidence(s)
/\ Sessions’ = (Sessions \ {s}) \cup {[s EXCEPT !.proceeded = TRUE]}
/\ UNCHANGED <<H, Active, CurrentR, CurrentH, Delivered>>
Commit(s) ==
/\ s \in Sessions
/\ s.proceeded = TRUE
/\ Active.status = "prepared"
/\ Active.record = s.pkg
/\ LiveAnchorCounter = s.pkg.anchor_counter
/\ H > 0
/\ H’ = H - 1
/\ Active’ = [Active EXCEPT !.status = "committed",
!.record.counter_committed = TRUE]
/\ UNCHANGED <<Sessions, CurrentR, CurrentH, Delivered>>
Accept(s) ==
/\ s \in Sessions
/\ s.proceeded = TRUE
/\ Active.status = "committed"
/\ Active.record = s.pkg
/\ PostEvidence(s.pkg)
/\ s.H_pre = H0 - s.pkg.anchor_counter
/\ s.pkg.H_post = H0 - s.pkg.next_anchor_counter
/\ s.pkg.next_anchor_counter = s.pkg.anchor_counter + 1
/\ Delivered’ = Delivered \cup {s.pkg}
/\ CurrentR’ = s.pkg.R_to
/\ CurrentH’ = s.pkg.h_to
/\ Active’ = [Active EXCEPT !.status = "ready",
!.anchor_counter = s.pkg.next_anchor_counter,
!.record = NULL]
/\ Sessions’ = Sessions \ {s}
/\ UNCHANGED H
Next == \E s, pkg:
Prepare(s, pkg) \/ Proceed(s) \/ Commit(s) \/ Accept(s)
Spec == Init /\ [][Next]_<<H, Active, CurrentR, CurrentH, Sessions, Delivered>>
NoCommitBeforeProceed ==
\A s \in Sessions:
Active.status = "committed" /\ Active.record = s.pkg => s.proceeded = TRUE
NoTwoAcceptedSameFrom ==
\A p, q \in Delivered:
/\ p # q
/\ p.R_from = q.R_from
/\ p.h_from = q.h_from
/\ p.anchor_counter = q.anchor_counter
31
=> FALSE
The model captures the essential point: acceptance requires a pre evidence object at the FROM
coordinate, a proceed gate before commit, and a post evidence object at the TO coordinate. A
post scalar alone is not an acceptance witness, and first transfer offline cannot commit before
BilateralBearerProceed.
33 Wire Protocol
The wire protocol separates pre counter evidence, post counter evidence, release certificate, and
first transfer offline prepared/proceed messages.
syntax = "proto3";
package dsm.anchor.v1;
message CounterEvidencePre {
bytes anchor_id = 1;
bytes receiver_challenge = 2;
bytes transition_digest = 3;
bytes root_advance_message = 4;
bytes sender_device_root_before = 5;
bytes sender_device_root_after = 6;
bytes appliance_root_before = 7;
bytes appliance_root_after = 8;
uint64 anchor_counter = 9;
uint64 next_anchor_counter = 10;
uint64 attested_raw_counter = 11;
bytes verifier_transcript = 12;
}
message CounterEvidencePost {
bytes anchor_id = 1;
bytes receiver_challenge = 2;
bytes transition_digest = 3;
bytes root_advance_message = 4;
bytes sender_device_root_before = 5;
bytes sender_device_root_after = 6;
bytes appliance_root_before = 7;
bytes appliance_root_after = 8;
uint64 anchor_counter = 9;
uint64 next_anchor_counter = 10;
uint64 attested_raw_counter = 11;
bytes verifier_transcript = 12;
}
message CounterAdvanceEvidence {
CounterEvidencePre pre = 1;
CounterEvidencePost post = 2;
bytes binding_hash = 3;
}
message AnchorDisclosure {
32
bytes anchor_bundle = 1;
bytes anchor_id = 2;
uint64 enrolled_raw_counter = 3;
bytes policy_hash = 4;
bytes pairing_public_key = 5;
bytes verifier_context = 6;
}
message BilateralBearerPrepared {
AnchorDisclosure disclosure = 1;
bytes session_id = 2;
bytes receiver_challenge = 3;
bytes transition_digest = 4;
bytes root_advance_message = 5;
bytes binding_hash = 6;
}
message BilateralBearerProceed {
bytes session_id = 1;
CounterEvidencePre pre = 2;
bytes binding_hash = 3;
}
message RootAdvanceCertificate {
bytes anchor_bundle = 1;
bytes prev_anchor_head = 2;
bytes next_anchor_head = 3;
bytes prev_boot_head = 4;
bytes next_boot_head = 5;
bytes sender_device_root_before = 6;
bytes sender_device_root_after = 7;
bytes appliance_root_before = 8;
bytes appliance_root_after = 9;
uint64 anchor_counter = 10;
uint64 next_anchor_counter = 11;
bytes transition_digest = 12;
bytes root_advance_message = 13;
bytes partition_commitment = 14;
bytes tropic_input = 15;
bytes witness_public_key_hash = 16;
bytes witness_public_key = 17;
bytes tropic_signature = 18;
bytes partition_signature = 19;
bytes anchor_id = 20;
uint32 tx_slot = 21;
bytes receiver_challenge = 22;
}
message OfflineRelease {
bytes canonical_transition = 1;
bytes boot_chain = 2;
RootAdvanceCertificate certificate = 3;
CounterAdvanceEvidence counter_evidence = 4;
}
33
message Envelope {
oneof payload {
BilateralBearerPrepared bilateral_bearer_prepared = 110;
BilateralBearerProceed bilateral_bearer_proceed = 111;
}
}
enum BleFrameType {
BLE_FRAME_TYPE_UNSPECIFIED = 0;
BILATERAL_BEARER_PREPARED = 16;
BILATERAL_BEARER_PROCEED = 17;
}
The old single CounterEvidence object is intentionally removed. A post counter scalar is not
sufficient evidence for offline bearer acceptance. The prepared and proceed messages exist only to
make first transfer offline safe; they do not weaken the acceptance predicate.
The transport adapter routes reply frames by payload type. A returned BilateralConfirm is sent
as a confirm frame. A returned BilateralBearerPrepared is sent as a BILATERAL BEARER PREPARED
frame. Unexpected payloads fail closed. BilateralBearerProceed is accepted only by the handler that
owns the stored prepared session.
34 Reference Implementation Requirements
The reference implementation must enforce the following:
(1) accept.rs keeps the FROM anchor state proof from Ri.
(2) accept.rs keeps the checked arithmetic rule ui + 1.
(3) accept.rs keeps the TO anchor state proof from Ri+1.
(4) accept.rs replaces post only counter verification with FROM to TO verification.
(5) The verifier interface must not return only a bare u64 counter scalar.
(6) The verifier must return or verify a transition bound CounterAdvanceEvidence object.
(7) The relay must expose a receiver side authenticated pre commit read before MCounter Update.
(8) The relay must expose a receiver side authenticated post commit read after MCounter Update.
(9) Both reads must bind the same receiver challenge and root advance message.
(10) TBCA or an equivalent transition bound counter advance transcript must be wired into pro-
duction verification and not left as dead code.
(11) First transfer offline must split prepare from commit.
(12) handle prepare response must return BilateralBearerPrepared, not confirm, when the opera-
tion is first transfer offline and the receiver enrollment material is present.
(13) The sender must store PreparedOfflineBearer and must not commit until a matching BilateralBearerProceed
arrives.
34
(14) BilateralBearerProceed must match the stored session identifier, receiver challenge, transition di-
gest, root advance message, anchor identifier, sender device roots, appliance roots, and counter
pair.
(15) The confirm path must consume a stored committed release. It must not rebuild a different
release for the same prepared session.
(16) Missing CounterEvidencePre, host supplied counter values, stale pre evidence, wrong session
proceed, or post only evidence must fail closed.
(17) If the relay reader or admitted anchor disclosure is unavailable, offline acceptance is refused
and the transfer routes online or fails closed.
The expected counter values are:
expected pre= H0−ui,
expected post= H0−(ui + 1).
A verifier that checks only:
H0−(ui + 1)
preserves the scalar counter gap and is not a valid implementation of this paper.
35 Verification Plan
The implementation must include tests for:
(1) honest FROM to TO transfer succeeds;
(2) old post only counter evidence is rejected;
(3) same FROM coordinate replay after first commit is rejected;
(4) stale pre evidence replay under a new receiver challenge is rejected;
(5) pre evidence for one transition spliced into another transition is rejected;
(6) two pre reads before one update cannot both produce accepted releases unless the update
receipt binds the same transition;
(7) root and counter mismatch is rejected;
(8) post device root that does not commit ui + 1 is rejected;
(9) anchor identifier mismatch is rejected;
(10) receiver challenge mismatch is rejected;
(11) partition certificate without TROPIC witness is rejected;
(12) TROPIC witness without DSM validity is rejected;
35
(13) committed recovery re emits the same release and does not sign another release;
(14) receiver handler captures the live FROM read before commit;
(15) production accept rejects stale FROM on CounterFromCoordinateInvalid or the equivalent im-
plementation error;
(16) first transfer offline prepare sends BilateralBearerPrepared and does not move the counter;
(17) sender commit is impossible before BilateralBearerProceed;
(18) receiver proceed carries or binds CounterEvidencePre;
(19) wrong session, wrong challenge, wrong transition, or stale BilateralBearerProceed fails closed;
(20) confirm uses the stored committed release from the prepared session;
(21) receiver captures TO after commit and verifies CounterAdvanceEvidence;
(22) first transfer offline replay after commit fails on stale FROM;
(23) transport adapter routes replies by payload type and rejects unexpected payloads.
36 Security Position
For programmable security between mutually distrustful parties, this design differs from a blockchain.
A blockchain protects double spend by global ordering under consensus assumptions. This authority
protects offline bearer transfer by deterministic local verification plus a physical counter coordinate
bound to sender state.
The security claim is not that hardware is magic. The claim is narrower and stronger:
no honest receiver accepts two releases from the same counter positioned sender state
unless the adversary breaks the stated cryptographic assumptions, forges the receiver witnessed
counter evidence, extracts and perfectly emulates the live hardware state, or violates the imple-
mentation requirements of this specification.
37 Security Summary
36
Part Provides Does not provide
Birth fuse non recreatable enrollment preimage live clone detection by itself
Anchor bundle immutable hardware and policy binding forward motion by itself
Boot ticket new hardware resume resistance DSM validity
Sender device root object state and expected fused anchor state hardware presence
Receiver challenge freshness and recipient binding uniqueness by itself
DSM transition proof valid root update hardware presence
RP2350 partition cert appliance partition lineage DSM validity by itself
TROPIC01 MACANDD enrolled hardware witness DSM validity
TROPIC01 counter stale FROM exposure and commit serialization perfect live clone detection
Fused anchor head DSM, partition, and TROPIC lineage binding value validity by itself
Accepted root frontier receiver side lineage continuity authenticity by itself at genesis
BilateralBearerPrepared first transfer disclosure before commit acceptance by itself
BilateralBearerProceed receiver witnessed FROM gate TO evidence by itself
Recovery record no orphaned committed release new authority by itself
Tripwire fork exposure on reconciliation instant awareness
38 Limits
(1) Perfect live state emulation is outside offline distinguishability. If an attacker extracts
and perfectly emulates the exact current non exportable state of the partition, TROPIC01,
and DSM authority state, no offline only protocol can distinguish that from the original.
(2) TROPIC01 physical extraction alone is not sufficient, but it is serious. If the secure
element is physically broken, offline bearer mode should be suspended and authority rotation
should occur unless policy explicitly allows continued risk.
(3) RP2350 breach can still cause denial of service. A breached RP2350 can waste counter
steps, corrupt local state, or force online recovery.
(4) Boot fencing is load bearing for new hardware rejection. A copied state image must
not be allowed to produce offline releases unless it first proves a boot chain from the committed
boot head.
(5) Receiver counter evidence is load bearing. The receiver must not accept host reported
counter state or a sender supplied live counter field.
(6) DSM proof verification is load bearing. The receiver must verify Ri →Ri+1. A hardware
certificate over an invalid root transition does not create value.
(7) Recovery durability is load bearing for liveness. If the counter moved, the same release
must remain recoverable. Otherwise the appliance risks an orphaned commit, which is a
liveness failure.
(8) New relationships are offline only through first transfer disclosure. A new indepen-
dent relationship may be accepted offline only when BilateralBearerPrepared, BilateralBearerProceed,
FROM evidence, commit, TO evidence, and the full predicate complete. Otherwise it routes
online or fails closed.
37
(9) Tripwire exposes later. Tripwire exposes forks on reconciliation. It is not instant awareness
for disconnected receivers.
(10) Strict frontier continuity can require online re admission after a rejected attempt.
The physical counter and appliance root may advance when a release is produced even if a
receiver ultimately rejects the confirm. A rejected attempt can open a gap between the sender
lineage and that receiver’s adopted frontier. A later transfer to the same receiver is refused at
the frontier check until online re admission reconciles the frontier. This is a liveness limitation,
not a safety one.
39 Conclusion
DSM offline bearer transfer requires more than a chip counter and more than a partition signature.
The counter must not be treated as a free scalar. The receiver must witness the physical counter at
the sender’s FROM coordinate before commit and at the sender’s TO coordinate after commit, with
both reads bound to the same transition digest, receiver challenge, sender device roots, appliance
roots, and anchor counter values.
First transfer offline requires one additional pairwise round trip. The sender prepares and
discloses but does not commit, the receiver admits the disclosure and captures FROM, the receiver
sends proceed, and only then does the sender commit and send confirm. This makes genesis offline
adoption use the same FROM to TO counter positioned commit as an established relationship.
The resulting object is:
(Ri,hi,ui) →(Ri+1,hi+1,ui + 1).
That is the Counter Positioned Commit. It makes the physical counter the coordinate of sender
state. A second same coordinate successor cannot be accepted because the physical counter has
already left the FROM coordinate and cannot return.
References
[1] Jack O’Connor, Jean-Philippe Aumasson, Samuel Neves, and Zooko Wilcox-O’Hearn. BLAKE3:
One Function, Fast Everywhere.
[2] Leslie Lamport. Specifying Systems: The TLA plus Language and Tools for Hardware and
Software Engineers.
[3] Ralph Merkle. A Certified Digital Signature. Advances in Cryptology, CRYPTO 1989.
38