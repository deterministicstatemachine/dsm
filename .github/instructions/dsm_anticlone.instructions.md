---
applyTo: '**'
---
Boot Fenced Fused Anchor Authority
for DSM Offline Bearer State
One Way Birth Fuse, Fused Anchor Head, RP2350 Partition Witness,
TROPIC01 MACANDD and Counter Evidence, Receiver Challenge,
Public DSM Verification, Recovery, and Tripwire Reconciliation
on Raspberry Pi Pico 2 W
Brandon Ramsay (Cryptskii)
Irrefutable Labs Inc.
June 2026
Abstract
A Deterministic State Machine, or DSM, advances state by local deterministic acceptance
rather than by global consensus. Ordinary DSM operation does not require a blockchain, validator set, sequencer, wall clock, or online settlement step on the common path.
Offline bearer transfer is the hard case. A receiver accepts a transfer while offline. The
receiver must not accept copied software pretending to be the live appliance, must not accept a
second use of the same spendable parent, and must not allow copied enrollment data to resume
on new hardware.
This paper specifies a compact offline bearer authority for DSM using a Raspberry Pi Pico 2
W, the RP2350 secure partition, and a MIKROE 6559 Secure Tropic Click carrying a TROPIC01
secure element. The design does not put all trust in TROPIC01 and does not put all trust in
the RP2350 partition. Instead, DSM, the partition, and TROPIC01 are fused into one forward
only lineage.
The authority is based on four rules:
destroy the birth preimage,
boot fence the appliance before offline use,
advance one DSM root and one fused anchor head together,
accept only authenticated TROPIC01 counter evidence and public DSM validity.
The DSM root commits to an immutable anchor bundle B, a fused anchor head Ai
, a
boot head Jb, and an anchor counter ui
. The anchor bundle binds the RP2350 partition key,
TROPIC01 anchor identifier, enrolled counter value H0, MACANDD slots, device identifier,
policy hash, and the hash of a destroyed one way birth fuse. The fused anchor head binds the
DSM root lineage, the partition lineage, and the TROPIC01 MACANDD and counter lineage.
Every boot must produce a boot ticket chained from the DSM committed boot head. Every
offline release must bind the current boot ticket. A copied state image on new hardware cannot
resume offline bearer mode because new hardware cannot advance the committed boot head
under the enrolled anchor bundle.
1
A release is accepted only if the receiver verifies the DSM transition, the receiver challenge,
the RP2350 partition certificate, the TROPIC01 MACANDD witness, authenticated TROPIC01
counter evidence, and the fused anchor head update. TROPIC01 evidence is necessary but not
sufficient. RP2350 partition evidence is necessary but not sufficient. DSM validity remains
public and receiver verified.
1 Purpose and Scope
This document specifies an optional DSM offline bearer authority. It is used only when a receiver
accepts a DSM transfer without online reconciliation at the moment of exchange.
The authority provides:
(1) one active SMT root for the appliance;
(2) one immutable anchor bundle;
(3) one forward only fused anchor head;
(4) one boot fenced offline session head;
(5) one physical counter derived anchor counter;
(6) one certified root advance at a time;
(7) receiver challenge binding;
(8) public verification of the DSM transition;
(9) RP2350 secure partition release evidence;
(10) TROPIC01 hardware presence through MACANDD;
(11) TROPIC01 counter evidence not trusted through the host;
(12) recovery by re emitting the same committed root advance;
(13) online fallback when local state, counter evidence, boot evidence, or policy does not match;
(14) Tripwire exposure of any fork on reconciliation.
The target hardware is:
Layer Part Role
Controller Raspberry Pi Pico 2 W host and transport board
MCU RP2350 secure partition and appliance policy
Secure element board MIKROE 6559 Secure Tropic Click TROPIC01 over SPI
Secure element TROPIC01 MACANDD, counter, R memory, pairing policy
Interface SPI at 3.3 V secure element command transport
2
The design does not require the RP2350 to verify the entire DSM transition. The receiver
verifies DSM validity. The RP2350 partition stores appliance state, signs partition certificates,
advances the boot ratchet, and drives TROPIC01. The receiver does not accept a root advance
merely because the RP2350 says it happened.
The design also does not let TROPIC01 authorize DSM state. TROPIC01 contributes hardware
witness output and authenticated counter evidence. DSM validity remains public and receiver
verified.
2 Design Summary
The appliance state includes:
Active = (hi
, B, Ai
, Jb, ui
,status,record).
Here:
• hi
is the active DSM SMT root;
• B is the immutable anchor bundle;
• Ai
is the active fused anchor head;
• Jb is the last DSM committed boot head;
• ui
is the active anchor counter;
• status ∈ {Ready, Prepared, Committed};
• record is empty, prepared, or committed.
The previous DSM state commits to:
(B, Ai
, Jb, ui).
A valid offline transfer from hi must advance to a next root hi+1 that commits to:
(B, Ai+1, Jb
′, ui + 1).
The release is not merely:
(hi
, ui) → (hi+1, ui + 1).
The fused form is:
(hi
, Ai
, Jb, ui) → (hi+1, Ai+1, Jb
′, ui + 1).
The receiver accepts only if:
(1) the previous root is the receiver accepted root for the object;
(2) the previous state commits to B, Ai
, Jb, ui
;
(3) a boot ticket or boot chain advances Jb to the current boot head Jb
′;
3
(4) the claimed next anchor counter is ui + 1;
(5) the DSM proof verifies hi → hi+1;
(6) the next root commits to B, Ai+1, Jb
′, ui + 1;
(7) the RP2350 partition certificate verifies over the same root advance message;
(8) the TROPIC01 MACANDD witness verifies over the same root advance message and partition
commitment;
(9) authenticated TROPIC01 counter evidence shows the live physical counter corresponds to
ui + 1;
(10) the receiver challenge matches;
(11) no policy event invalidates the anchor.
The core rule is:
The receiver accepts only when DSM, the RP2350 partition, and TROPIC01 all bind the same root advance and3 Naming Discipline
The protocol uses the following names.
Name Meaning
prev root SMT root advanced from
next root SMT root advanced to
anchor counter derived increasing DSM value u = H0 − H
next anchor counter required next value u + 1
enrolled counter enrolled TROPIC01 physical counter value H0
attested live counter raw authenticated TROPIC01 value H
anchor bundle immutable enrollment digest B
anchor head fused anchor head Ai
boot head boot fence head Jb
The anchor counter is not the raw TROPIC01 counter. The anchor counter increases:
u = H0 − H.
The raw TROPIC01 counter counts down:
H ← H − 1.
The receiver computes:
uattested = H0 − Hattested.
The receiver accepts only if:
uattested = ui + 1.
4
4 Why a Counter Alone Is Not the Design
A chip signature over transfer details and a counter gives an ordered hardware log. It does not by
itself prove that a proposed transfer is a valid DSM successor from the receiver accepted previous
root. It also does not prove that the release came from the correct fused appliance lineage.
The useful object is not:
Signk
(transfer ∥ u).
The useful object is:
(hi
, Ai
, Jb, ui) → (hi+1, Ai+1, Jb
′, ui + 1),
where hi
is a DSM root the receiver recognizes, hi commits to the current fused anchor state,
and hi+1 is verified as the valid successor root for the transfer.
The anchor counter orders hardware events. The fused anchor head binds the hardware lineages.
DSM validity decides whether the state transition is real.
5 Cryptographic Preliminaries
Let H denote BLAKE3 256, modeled as collision resistant and resistant to second preimages. Let
HKDF denote a domain separated key derivation function.
Let (StepKeyGen, StepSign, StepVerify) be the witness signature scheme fixed by the appliance
profile. The concrete profile in this document is wots over BLAKE3.
Let (PartSign, PartVerify) be the RP2350 secure partition signature scheme under a partition
key generated at appliance birth and bound into the anchor bundle.
All structured objects use canonical byte encoding. If X is structured, enc(X) means its canonical byte encoding. Verifiers reject non canonical encodings.
Definition 1 (DSM Root). A DSM root is the sparse Merkle tree root that commits to the current
local DSM state, including relationship tips, object leaves, authority policy, anchor bundle, fused
anchor head, boot head, and anchor counter used for offline bearer mode.
Definition 2 (Spendable Parent). A spendable parent is a DSM root hi that commits to a spendable object, owner, relationship context, authority policy, anchor bundle B, fused anchor head Ai
,
boot head Jb, and anchor counter ui
. A valid offline bearer transfer must consume that spendable
parent into one successor root.
Definition 3 (Offline Bearer Transfer). An offline bearer transfer is a DSM transition accepted
without querying a network, storage node, ledger, validator, sequencer, or clock service at the moment of exchange. Acceptance is decided from canonical DSM bytes, SMT proofs, receiver challenge
binding, boot ticket verification, partition certificate verification, hardware witness verification, authenticated TROPIC01 counter evidence, fused anchor head verification, and the receiver accepted
previous root.
Definition 4 (Anchor Counter). The anchor counter is the derived increasing DSM value:
u = H0 − H.
Here H0 is the TROPIC01 counter value at enrollment and H is the live TROPIC01 counter
value. TROPIC01 counters count down, so each successful counter update maps H ← H − 1 and
u ← u + 1.
5
6 Threat Model
Definition 5 (Software Clone). A software clone receives all host readable wallet state:
Clone = (seed, keys, chain history, local database, cached proofs, host files, application state).
The clone may run on another phone, emulator, rooted host, or modified controller. It does
not receive RP2350 secure partition non exportable state or TROPIC01 internal MACANDD and
counter state.
Definition 6 (New Hardware Clone). A new hardware clone is a device that has copied host
readable state and enrollment data, but has different RP2350 partition state, different TROPIC01
state, different partition key, different TROPIC01 anchor identifier, different MACANDD slot state,
or different physical counter state.
Definition 7 (RP2350 Partition Breach). An RP2350 partition breach means the attacker can
make arbitrary policy side calls, modify local appliance state, or drive the software around TROPIC01
incorrectly. The protocol does not rely on RP2350 claims alone for receiver acceptance. Such a
breach may cause denial of service, counter wasting, invalid certificates, or a bricked local anchor.
It must not make an honest receiver accept an invalid DSM transition or a second valid successor
from the same spendable parent unless the other required evidence also verifies.
Definition 8 (TROPIC01 Physical Break). A TROPIC01 physical break means the attacker extracts or forges the secure element state needed to produce MACANDD outputs or counterfeit
counter evidence. This is outside ordinary TROPIC-only security. In this fused design, TROPIC01
break alone is still insufficient because receiver acceptance also requires the RP2350 partition certificate, DSM proof, boot ticket, and fused anchor head update.
Definition 9 (Perfect Live State Clone). A perfect live state clone is an adversary that extracts
the exact current non exportable state of the RP2350 partition, the exact current non exportable
TROPIC01 MACANDD and counter state, all DSM authority state, and can emulate those states
perfectly without divergence. No offline-only protocol can distinguish such an exact emulation from
the original device.
Definition 10 (Double Spend). A double spend exists if two distinct transitions:
τA : hi → hA, τB : hi → hB, hA ̸= hB,
consume the same spendable parent hi and both satisfy the DSM offline bearer acceptance
predicate for honest receivers.
Definition 11 (Closed Branch). A closed branch is a branch created among devices controlled by
the same adversary. It may be internally consistent only inside that adversary controlled set. Since
new independent relationships require online reconciliation, the branch breaks when it meets real
reconciliation or an honest counterparty that checks the fused anchor lineage, counter evidence,
and DSM root lineage.
6
7 One Way Birth Fuse
The first hardening step is to make enrollment non recreatable from public enrollment data.
Definition 12 (One Way Birth Fuse). The one way birth fuse sbirth is a secret enrollment preimage
formed from RP2350 partition entropy, TROPIC01 birth witness material, host entropy, device
context, and authority policy. The public anchor bundle and initial fused heads commit only to
H(sbirth). The preimage sbirth is destroyed immediately after deriving the initial private ratchet
state.
At birth, the appliance samples or derives:
sbirth = H("DSM/anchor/birth-secret/v1"∥partition trng∥tropic birth witness∥host nonce∥device id∥policy hash).
The public birth commitment is:
Sbirth = H(sbirth).
The raw sbirth is never exported.
Remark 13. The enrolled TROPIC01 counter value H0 is not destroyed. Receivers need H0, or a
policy pinned equivalent, to verify u = H0 − H. The destroyed value is the birth preimage sbirth,
not H0.
8 Anchor Bundle
Definition 14 (Anchor Bundle). The anchor bundle B is the immutable enrollment digest binding the partition public key, partition device identifier, TROPIC01 anchor identifier, enrolled
TROPIC01 counter value H0, MACANDD boot slot, MACANDD transfer slot, DSM device identifier, authority policy, and the hash of the destroyed one way birth fuse.
Let qboot be the MACANDD slot used for boot fencing. Let qtx be the MACANDD slot used
for transfer witnesses. Then:
B = H("DSM/anchor-bundle/v1"∥partition pk∥partition device id∥tropic anchor id∥H0∥qboot∥qtx∥device id∥policy haOffline bearer releases under a different bundle are not valid successors of roots committed to
B.
9 Initial Fused State
The first fused anchor head is:
A0 = H("DSM/fused-anchor-head/init/v1" ∥ B ∥ h0 ∥ 0 ∥ Sbirth).
The first boot head is:
J0 = H("DSM/fused-boot-head/init/v1" ∥ B ∥ A0 ∥ 0 ∥ Sbirth).
The initial partition ratchet is:
7
p0 = HKDF(secret = sbirth, context = "DSM/partition-ratchet-seed/v1" ∥ B ∥ A0 ∥ J0).
After deriving p0, the appliance destroys:
sbirth ← ⊥.
The device carries only forward moving private state:
(pi
,TROPIC01 MACANDD boot slot,TROPIC01 MACANDD transfer slot, H).
The public DSM state carries:
(B, Ai
, Jb, ui).
10 Fused Anchor Head
Definition 15 (Fused Anchor Head). The fused anchor head Ai
is the DSM committed digest of the
current offline bearer anchor lineage. It binds the DSM root lineage, the RP2350 secure partition
lineage, and the TROPIC01 MACANDD and counter lineage into one non interchangeable state.
A candidate offline successor must advance:
Ai → Ai+1.
The next DSM root must commit to Ai+1. A release that does not produce the next fused
anchor head is not an offline bearer successor.
11 Boot Fenced Fused Anchor
Definition 16 (Boot Fenced Fused Anchor). Offline bearer mode is enabled only after the appliance
produces a boot ticket chained from the DSM committed boot head. The boot ticket is produced
internally by the firmware target from a device authoritative boot measurement, the RP2350 secure
partition boot ratchet, and a TROPIC01 boot MACANDD slot. A host request cannot drive boot
head advancement and cannot supply an attacker chosen firmware measurement. Every offline
release binds the current boot ticket or boot chain. A copied state image on new hardware cannot
resume offline bearer mode because the new hardware cannot advance the committed boot head
under the enrolled anchor bundle.
On boot, the firmware target advances:
Jb → Jb+1.
The boot input is formed from device internal state:
Xboot
b+1 = H("DSM/boot-fuse-input/v1"∥B∥Ai∥Jb∥boot seq∥firmware measurement∥partition device id).
The values boot seq and firmware measurement are device supplied. They are not fields accepted
from the host transport request.
8
TROPIC01 consumes the boot MACANDD slot:
W
T,boot
b+1 = MACANDD(qboot, Xboot
b+1 ).
The partition advances its boot ratchet:
pb+1 = H("DSM/partition-boot-ratchet/v1"∥pb∥W
T,boot
b+1 ∥B∥Ai∥Jb∥boot seq∥firmware measurement).
The old partition ratchet is erased:
pb ← ⊥.
The partition boot certificate message is:
MP
boot,b+1 = H("DSM/partition-boot-cert/v1"∥B∥Ai∥Jb∥Xboot
b+1 ∥H(W
T,boot
b+1 )∥boot seq∥firmware measurement).
The partition signs:
σ
P
boot,b+1 = PartSign(MP
boot,b+1).
The fixed width boot signature commitment is:
Σ
P
boot,b+1 = SigCommit(σ
P
boot,b+1).
The new boot head is:
Jb+1 = H("DSM/fused-boot-head/v1"∥B∥Ai∥Jb∥Xboot
b+1 ∥H(pb+1)∥H(W
T,boot
b+1 )∥Σ
P
boot,b+1∥firmware measurement).
The boot ticket is:
BootTicketb+1 = (B, Ai
, Jb, Jb+1, boot seq, firmware measurement, σP
boot,b+1, Xboot
b+1 ,tropic boot witness).
If multiple boots occur between DSM transfers, the release carries a boot chain:
BootChain = (BootTicketb+1, . . . ,BootTicketb+k),
which proves:
Jb → Jb+k.
The next DSM root commits to the latest boot head used by the release.
9
12 State Bound to the Previous Root
The key simplification is to put the fused anchor state into the DSM state committed by the
previous root.
A spendable parent root hi commits to:
(object id, owner, balance or object state,relationship context, authority policy hash, B, Ai
, Jb, ui).
Therefore the only valid offline successor anchor counter is:
ui+1 = ui + 1.
A receiver that sees a candidate transfer from hi rejects it unless the candidate release proves:
(hi
, Ai
, Jb, ui) → (hi+1, Ai+1, Jb
′, ui + 1).
This removes the need for a table of offered or pending precommits. The previous root itself
carries the expected fused anchor state.
13 TROPIC01 Counter Evidence
The receiver must not trust a host string that says “the counter moved.” The receiver must also
not treat a sender supplied live counter field as proof. That value is only a claim unless it is
authenticated by TROPIC01.
Definition 17 (Counter Evidence). Counter evidence for a release is evidence that the pinned
TROPIC01 counter has reached the live physical value corresponding to ui + 1. It is accepted only
if obtained by one of:
(1) a receiver operated authenticated L3session to TROPIC01 through a verifier pairing slot, where
the host only relays encrypted packets;
(2) a TROPIC01 primitive that directly authenticates the live counter value under a key pinned
by the receiver;
(3) a provisioning transcript and live audit rule that is explicitly accepted by the authority policy.
The accepted counter value is the value obtained by the receiver through an allowed counter
evidence path. The preferred path is an authenticated L3verifier session. The receiver is the
endpoint and the phone or Pico only relays encrypted packets.
The receiver reads the live counter value Hattested from TROPIC01 and checks:
Hattested = H0 − (ui + 1).
Equivalently, the receiver derives:
uattested = H0 − Hattested
and requires:
uattested = ui + 1.
10
The RP2350 may relay packets, but it is not the trusted endpoint. The release may carry a
counter field for transport convenience, but that field is not trusted. The receiver accepts only the
transcript attested value, or another policy approved TROPIC01 authenticated counter value.
Remark 18. If the receiver cannot obtain authenticated counter evidence, the receiver does not
accept offline bearer mode. The transfer routes to online checked mode.
14 TROPIC01 MACANDD Witness
MACANDD is used as a hardware witness. It is not used as standalone transaction authority.
Definition 19 (MACANDD Command Shape). A MACANDD call is modeled as:
W = MACANDD(q, X),
where q is a MACANDD slot index, X ∈ {0, 1}
256 is a 32 byte input, and W ∈ {0, 1}
256 is the
32 byte output returned by TROPIC01 over an authenticated L3session.
Definition 20 (MACANDD Slot Evolution). Let Vt be the old slot state before a MACANDD
call. Let X be the input. The call computes a new state:
Vt+1 = F1(X ∥ q),
stores Vt+1, and returns:
Wt = F2(Vt ∥ Vt+1 ∥ q).
The functions F1 and F2 are keyed inside TROPIC01. The host does not know their keys.
15 DSM Transition Digest
Let ∆i+1 be the canonical DSM transition package. It contains the action, recipient, object identifier, payload, old leaf proof, new leaf proof, and all data required for the receiver to verify:
hi → hi+1.
The transition digest is:
Di+1 = H("DSM/root-advance/transition-digest/v1" ∥ enc(∆i+1)).
The receiver supplies a fresh random challenge:
rR
$←− {0, 1}
256
.
The challenge is bound into the boot fenced root advance message and release. A release for
one receiver challenge is not accepted for another challenge.
11
16 Boot Bound Root Advance Message
Let Jb
′ be the current boot head proven by a boot ticket or boot chain from the DSM committed
boot head Jb.
The boot bound root advance message is:
Mi+1 = H("DSM/fused-root-advance-message/v1"∥B∥Ai∥Jb
′∥hi∥hi+1∥ui∥(ui+1)∥Di+1∥recipient device id∥objecEvery partition certificate and TROPIC01 transfer witness must bind this same message.
17 Partition Commitment and TROPIC Cross Binding
The partition first commits to the root advance message. The code authoritative partition commitment has no partition epoch and no partition nonce. The wire certificate carries only the fields
below, and the verifier recomputes the commitment from those fields:
C
P
i+1 = H("DSM/partition-commit/v1" ∥ B ∥ Ai ∥ Jb
′ ∥ Mi+1).
The TROPIC01 transfer witness input includes that partition commitment:
XT
i+1 = H("DSM/tropic-fused-transfer-input/v1" ∥ B ∥ Ai ∥ Jb
′ ∥ Mi+1 ∥ C
P
i+1 ∥ qtx).
TROPIC01 returns:
WT
i+1 = MACANDD(qtx, XT
i+1).
The witness signing seed is:
KT
i+1 = HKDF
secret = WT
i+1, context = "DSM/tropic/fused-transfer-witness-key/v1" ∥ XT
i+1 ∥ Mi+1 ∥ B ∥ Aihe witness key pair is:
(skhw, pkhw) = StepKeyGen(KT
i+1).
The public key handle is:
Phw = H("DSM/tropic/pk-hash/v1" ∥ pkhw).
The TROPIC witness message is:
MT
i+1 = H("DSM/tropic/fused-transfer-witness-message/v1" ∥ Mi+1 ∥ C
P
i+1 ∥ XT
i+1 ∥ Phw).
The TROPIC witness signature is:
σ
T
i+1 = StepSign(skhw, MT
i+1).
The fixed width TROPIC signature commitment is:
12
Σ
T
i+1 = SigCommit(σ
T
i+1).
The partition final certificate binds the TROPIC witness commitment back into the partition
lineage:
MP
i+1 = H("DSM/partition-final-cert/v1" ∥ B ∥ Ai ∥ Jb
′ ∥ Mi+1 ∥ C
P
i+1 ∥ Phw ∥ Σ
T
i+1 ∥ (ui + 1)).
The partition certificate is:
σ
P
i+1 = PartSign(MP
i+1).
The fixed width partition signature commitment is:
Σ
P
i+1 = SigCommit(σ
P
i+1).
The cross binding is:
C
P
i+1 → XT
i+1 → Σ
T
i+1 → MP
i+1 → Σ
P
i+1.
Thus the TROPIC witness is bound to the partition commitment, and the partition final certificate is bound back to the TROPIC witness commitment. Neither proof can be swapped out for
a proof from another device, another boot, another root transition, or another anchor bundle.
18 Next Fused Anchor Head
After the receiver obtains authenticated counter evidence, the next fused anchor head is:
Ai+1 = H("DSM/fused-anchor-head/v1" ∥ B ∥ Ai ∥ Jb
′ ∥ Mi+1 ∥ C
P
i+1 ∥ Σ
P
i+1 ∥ Phw ∥ Σ
T
i+1 ∥ Hattested).
The next DSM root hi+1 must commit to:
(B, Ai+1, Jb
′, ui + 1).
The receiver verifies that hi committed to the old fused anchor state and that hi+1 commits to
the new fused anchor state.
19 Witness Signature Scheme
The appliance profile uses wots over BLAKE3. The witness key signs exactly one digest, so a one
time signature is sufficient.
Definition 21 (wots Parameters). Let n = 32, w = 16, ℓ1 = 64, ℓ2 = 3, and ℓ = 67. A signature
is:
ℓ · n = 2144
bytes. The compressed public key is 32 bytes.
13
Definition 22 (Chain Function). The chain function is:
F(x) = H("DSM/anchor/wots-chain/v1" ∥ x).
For seed K and chain index j:
sj = HKDF(secret = K, context = "DSM/anchor/wots-sk/v1" ∥ enc16(j)).
Definition 23 (StepKeyGen, StepSign, StepVerify). The key generation, signing, and verification
algorithms are the standard Winternitz chain construction over BLAKE3:
StepKeyGen(K) → (skhw, pkhw),
StepSign(skhw, d) → σ,
StepVerify(pkhw, d, σ) → {0, 1}.
The secret key is the seed K. It is retained only long enough to sign the release, then erased.
Assumption 24 (Witness Signature Security). Given pkhw and one signature on digest d, no
efficient adversary can produce a valid signature on d
′ ̸= d except with negligible probability,
assuming the preimage and second preimage resistance of H.
20 Root Advance Certificate
The root advance certificate is:
Certi+1 = (B, Ai
, Ai+1, Jb, Jb
′, hi
, hi+1, ui
, ui+1, Di+1, Mi+1, CP
i+1, XT
i+1, Phw, pkhw, σT
i+1, σP
i+1, anchor id, qtx, rR).
The release package is:
Pkgi+1 = (∆i+1, BootChain, Certi+1, counter evidencei+1).
21 Compact Appliance Protocol
The appliance has three transfer states:
Ready, Prepared, Committed.
Boot state is separate. Offline transfer is disabled until a valid boot ticket or boot chain exists
for the current boot.
14
21.1 Boot
Boot is device internal. The host transport does not submit a boot operation, boot sequence, or
firmware measurement. On boot, the appliance:
(1) reads the active B, Ai
, Jb, ui
;
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
21.2 Prepare
The sender proposes ∆i+1, hi
, and hi+1. The receiver checks the proposed transfer at the human
and DSM level, then supplies rR.
The appliance checks:
Active.status = Ready,
Active.h = hi
,
Active.B = B,
Active.A = Ai
,
Active.u = ui
,
ui = H0 − H.
The expression H0 − H is computed with checked subtraction. If H > H0, the state is rejected
as a counter mismatch because a down counter cannot report a value above its enrolled value.
The appliance verifies that a boot ticket or boot chain exists from the DSM committed boot
head to the current boot head Jb
′.
It constructs Di+1, Mi+1, C
P
i+1, and XT
i+1. It calls MACANDD on the transfer slot, derives the
witness key, forms the TROPIC witness, forms the partition final certificate, computes Ai+1, and
constructs Certi+1 without exporting it yet.
It writes a durable prepared record:
15
Active ← (hi
, B, Ai
, Jb
′, ui
, Prepared, Certi+1, ∆i+1,skhw).
No counter has moved. No release has been exported.
21.3 Commit
The appliance forms the release package without counter evidence and stores the committed candidate durably with:
counter committed = false.
Before moving the counter, the appliance re pins the live anchor counter:
H0 − H = ui
.
If this check fails, the operation downgrades to online recovery and does not move the counter.
If H = 0, the operation returns:
EXHAUSTED ONLINE ONLY.
No release is exported or committed from an exhausted counter.
If H > 0, the appliance issues:
MCounter Update.
A successful counter update maps:
H ← H − 1.
The appliance marks the committed candidate as:
counter committed = true
and erases skhw. The post commit physical counter value is the actual decremented reading
H − 1, not a value reconstructed from H0 − (ui + 1).
21.4 Counter Evidence
The receiver obtains counter evidence from TROPIC01. In the preferred mode, the receiver opens
an authenticated L3verifier session through a verifier pairing slot, with the host relaying encrypted
packets only.
The receiver obtains Hattested and checks:
Hattested = H0 − (ui + 1).
If this check fails, the receiver rejects offline bearer acceptance.
21.5 Emit
The appliance may export the release only after the counter commit. The receiver attaches or
records authenticated counter evidence and verifies Pkgi+1.
16
21.6 Finalize
After emitting the release, the appliance may finalize only if the active anchor counter equals the
live counter derived anchor counter:
Active.u = H0 − H.
If this check fails, finalization is refused and the appliance enters online recovery.
If the check holds, finalization writes:
Active ← (hi+1, B, Ai+1, Jb
′, ui + 1, Ready, ∅).
If power fails before finalize, recovery re emits the same committed release and finalizes the
same successor.
22 Receiver Acceptance Predicate
A receiver accepts an offline bearer transfer only if all checks hold.
Definition 25 (Boot Fenced Fused Root Advance Acceptance). Let Acceptoff(Pkgi+1) = 1 iff:
(1) all encodings are canonical;
(2) hi
is the receiver accepted previous root for the received object;
(3) hi commits to B, Ai
, Jb, ui
;
(4) the boot ticket or boot chain verifies Jb → Jb
′;
(5) the claimed next anchor counter is ui + 1, using checked arithmetic;
(6) the receiver challenge rR is the challenge supplied by this receiver;
(7) Di+1 recomputes from ∆i+1;
(8) Mi+1 recomputes from the bound fields;
(9) C
P
i+1 recomputes from the partition commitment fields;
(10) XT
i+1 recomputes from B, Ai
, Jb
′, Mi+1, CP
i+1, qtx;
(11) Phw = H("DSM/tropic/pk-hash/v1" ∥ pkhw);
(12) MT
i+1 recomputes and
StepVerify(pkhw, MT
i+1, σT
i+1) = 1;
(13) MP
i+1 recomputes and
PartVerify(partition pk, MP
i+1, σP
i+1) = 1;
(14) the DSM transition proof verifies hi → hi+1;
(15) the transfer gives the claimed object or value to the receiver;
(16) the authority policy hash matches the previous state;
17
(17) the receiver obtains an authenticated TROPIC01 counter value Hattested;
(18) the authenticated counter value satisfies
Hattested = H0 − (ui + 1);
(19) equivalently, the receiver derives
uattested = H0 − Hattested
and verifies
uattested = ui + 1;
(20) Ai+1 recomputes from the fused anchor head formula;
(21) hi+1 commits to B, Ai+1, Jb
′, ui + 1;
(22) no known firmware boundary event, physical compromise event, or policy event invalidates the
anchor.
The receiver trusts public DSM verification, the receiver challenge, the boot ticket, the partition certificate, the hardware witness signature, the fused anchor head update, and authenticated
TROPIC01 counter evidence. The receiver does not trust host state, copied wallet files, a Pico
reported counter value, or any unauthenticated counter field carried inside the release.
23 What Happens if RP2350 Is Breached
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
A partition certificate without a matching TROPIC01 transfer witness fails. A partition certificate without authenticated TROPIC01 counter evidence fails. A partition certificate over an
invalid DSM transition fails.
18
24 What Happens if TROPIC01 Is Broken
TROPIC01 is not the sole authority.
If TROPIC01 is broken alone, the attacker may try to forge hardware witness output or counter
evidence. That is still not enough for an honest receiver because the release also requires:
• the DSM transition proof;
• the previous root commitment to B, Ai
, Jb, ui
;
• a valid boot ticket or boot chain;
• a valid RP2350 partition certificate;
• a valid fused anchor head update;
• the next root commitment to B, Ai+1, Jb
′, ui + 1.
A TROPIC-only break becomes offline mode suspension and authority rotation unless the other
fused anchor predicates also fail.
25 Why New Hardware Cannot Resume
A copied state image can contain:
B, Ai
, Jb, ui
, history, cached proofs, public enrollment data.
A new device cannot advance the boot head:
Jb → Jb+1
unless it has the enrolled RP2350 partition boot ratchet and the enrolled TROPIC01 boot
MACANDD slot state. A new partition key, new partition state, new TROPIC01 anchor identifier,
new MACANDD slot state, or new physical counter gives a different lineage.
Therefore a release from new hardware fails one of:
• anchor bundle equality;
• boot chain verification;
• partition certificate verification;
• TROPIC01 boot witness verification;
• TROPIC01 transfer witness verification;
• authenticated counter evidence;
• fused anchor head recomputation;
• next root commitment.
New hardware requires online authority rotation. It cannot continue offline from a root committed to another bundle and fused anchor head.
19
26 Power Loss Behavior
Power may fail between any two operations.
26.1 Before Boot Ticket Is Durable
Offline bearer mode is disabled. Recovery must produce a valid boot ticket or route to online
checked recovery.
26.2 After Boot Ticket Is Durable
Offline bearer mode may proceed if the boot ticket verifies from the DSM committed boot head. If
the boot ticket is malformed, stale, or not chained from the committed boot head, offline mode is
refused.
26.3 Before Prepared Is Durable
No counter has moved and no release has been exported. Recovery returns to Ready if anchor state
is consistent. Otherwise the appliance enters online checked recovery.
26.4 After Prepared Is Durable
The prepared record may complete if skhw and the partition record are present. If required private
state is missing, the transfer cannot complete offline and must be cancelled or resolved online. No
second transfer from the same active root is allowed while the prepared record exists.
26.5 After Release Is Durable but Before Counter Commit
Recovery may commit the same release if the previous root, boot head, fused anchor head, and
policy still match. Since no release was exported before counter commit, no receiver has accepted
an uncommitted spend.
26.6 After Counter Moved but Before Commit Flag Was Durable
If the physical counter moved but counter committed was not durably written, recovery does not
move the counter again. If the committed candidate target anchor counter already equals the live
counter derived anchor counter, recovery marks the candidate committed and re emits the same
release.
26.7 After Counter Commit but Before Export
The counter has moved and the release is durable. Recovery re emits the same release package. It
does not sign a new one.
26.8 After Export but Before Finalize
Recovery re emits the same release and finalization advances to the same hi+1, guarded by:
Active.u = H0 − H.
20
27 Recovery
Recovery must preserve the exact committed release until it has been re emitted and finalized. It
must not erase the committed release merely because recovery found it.
The recovery rule is:
if a committed release exists, re emit that same release and finalize that same successor.
The appliance does not sign a new release during recovery.
(1) If the appliance is in Ready, recovery checks that the stored anchor counter equals the live
counter derived anchor counter. If the stored anchor counter is lower, the appliance enters
online recovery. If the stored anchor counter is higher, the appliance fails closed.
(2) If the appliance is in Prepared, recovery checks that the previous root still equals the active
root, the boot head is valid, and the live anchor counter still equals the record anchor counter.
If the witness key and partition record are present, the prepared record may complete. If
required private state is missing, the record must be cancelled or resolved online.
(3) If a committed candidate exists with counter committed = false and its target anchor counter
is ulive + 1, recovery may complete the counter update only if the candidate previous root still
equals the active root and the boot/fused anchor state still matches. This prevents recovery
from burning a counter step for a stale or divergent previous root.
(4) If a committed candidate exists with counter committed = false but the live counter already
equals the candidate target anchor counter, recovery marks the candidate committed without
moving the counter again. This covers the interruption case where the physical counter moved
but the committed flag was not durably written.
(5) If a committed candidate exists with counter committed = true, recovery returns a re emit
outcome. The record remains committed until the same release is emitted and finalized.
(6) Finalize is allowed only if the active anchor counter equals the live counter derived anchor
counter:
Active.u = H0 − H.
This prevents frontier advance when local state and the physical counter disagree.
28 Recovery Algorithm
recover(H0, H, Active):
live_anchor_counter = checked_sub(H0, H)
if live_anchor_counter == ERROR:
return COUNTER_MISMATCH
if firmware_boundary_invalid():
return DOWNGRADE_ONLINE
if rmemory_map_invalid():
return DOWNGRADE_ONLINE
21
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
if Active.anchor_counter < live_anchor_counter:
return DOWNGRADE_ONLINE
if Active.anchor_counter > live_anchor_counter:
return FAIL_CLOSED
if H == 0:
return EXHAUSTED_ONLINE_ONLY
22
return ACCEPT(Active.root)
return DOWNGRADE_ONLINE
29 Online Checked Mode and New Relationships
New independent relationships are not created under this offline bearer authority. They require
online checked reconciliation. This matters for collusive closed branches.
If the same adversary controls both sides of an offline exchange, it can create a private branch
that only its own devices accept. That does not affect honest receivers. When the branch attempts
to meet real reconciliation or a new independent relationship, the DSM root, anchor bundle, fused
anchor head, boot head, anchor counter, and counter evidence no longer line up. The branch has
become its own reality and breaks away from the accepted one.
Therefore the meaningful security target is an honest receiver accepting value from a sender. A
closed adversary branch is not a successful attack on anyone else.
30 Tripwire Composition
Tripwire supplies fork exposure on reconciliation. Each device commits relationship tips into a per
device sparse Merkle tree. A valid receipt proves adjacency from an old root to a new root and
binds the relevant relationship tip update.
Tripwire does not make offline receivers instantly aware of each other. It exposes conflicting
accepted tips when they are compared.
Assumption 26 (Tripwire Security). Assume the hash function is collision resistant and DSM signatures are secure against chosen message forgery. Then two distinct accepted successors from the
same predecessor cannot survive reconciliation without a hash collision, signature forgery, violated
DSM predicate, or violated hardware evidence condition.
31 Security Claims
Theorem 27 (Birth Non Recreation). Public enrollment data is insufficient to recreate the initial
fused anchor lineage on new hardware.
Proof. The anchor bundle, initial fused anchor head, initial boot head, and initial partition ratchet
are derived from sbirth, but only H(sbirth) is public. The preimage sbirth is destroyed after deriving
the initial private ratchet. A new device that has only public enrollment data cannot derive p0,
the TROPIC01 MACANDD slot state, or the same fused anchor lineage except by inverting H,
extracting the original non exportable state, or perfectly emulating the original device state.
Theorem 28 (No New Hardware Resume). Let a DSM root commit to anchor bundle B, fused
anchor head Ai, boot head Jb, and anchor counter ui. A device with different partition hardware
state or different TROPIC01 boot state cannot produce an accepted offline bearer successor from that
root, except by forging the partition boot certificate, forging the TROPIC01 boot witness, breaking
the hash binding, or extracting and perfectly emulating the original non exportable live states.
23
Proof. An accepted release requires a boot ticket or boot chain from Jb to Jb
′. The boot ticket is
produced from the RP2350 partition boot ratchet and the TROPIC01 boot MACANDD slot under
the committed bundle B. New hardware has a different partition state, different TROPIC01 state,
or a different bundle. Therefore it cannot advance the committed boot head to the accepted current
boot head unless it forges the required evidence or exactly emulates the original non exportable
live states.
Theorem 29 (Clone Exclusion). A software clone cannot produce an accepted offline bearer root
advance for an enrolled authority unless it obtains the original partition evidence and TROPIC01
MACANDD output, or forges one of the required signatures.
Proof. An accepted release requires a valid boot ticket, partition certificate, TROPIC witness
signature, authenticated TROPIC01 counter evidence, DSM transition proof, and fused anchor
head update. A software clone may copy host files and wallet state, but it does not have the
RP2350 partition ratchet, partition signing state, TROPIC01 MACANDD slot state, or live counter.
Therefore it cannot produce the accepted evidence set unless it obtains those non exportable states
or forges the required evidence.
Theorem 30 (Root Rebinding Exclusion). A witness produced for one root advance cannot be
accepted for another root advance except with negligible probability.
Proof. The boot bound root advance message Mi+1, partition commitment C
P
i+1, TROPIC input
XT
i+1, partition certificate, TROPIC witness, and fused anchor head bind the anchor bundle, previous fused anchor head, current boot head, previous root, next root, anchor counter, next anchor
counter, transition digest, recipient, object, policy, and receiver challenge. Changing any of those
values changes the verified messages. The old evidence no longer verifies except through hash
collision, signature forgery, or a break of the witness scheme.
Theorem 31 (Counter Step Uniqueness). For a previous root that commits to ui, an honest receiver
accepts only a release whose authenticated TROPIC01 counter evidence proves the next anchor
counter ui + 1.
Proof. The receiver reads ui from the previous DSM state and requires ui + 1 as the next anchor
counter. Authenticated counter evidence must show the live TROPIC01 counter value:
H0 − (ui + 1).
A second attempted transfer from the same spendable parent after a counter commit cannot
present the same authenticated live counter evidence, because the physical counter cannot increase
or reset under the counter assumption.
Theorem 32 (TROPIC01 Is Necessary but Not Sufficient). A TROPIC01 witness and counter
value alone do not authorize an offline bearer transfer.
Proof. The receiver acceptance predicate also requires public DSM transition validity, previous root
commitment to the fused anchor state, boot ticket verification, partition certificate verification,
receiver challenge binding, fused anchor head recomputation, and next root commitment to the
new fused anchor state. TROPIC01 evidence alone cannot satisfy those checks.
Theorem 33 (Partition Is Necessary but Not Sufficient). An RP2350 partition certificate alone
does not authorize an offline bearer transfer.
24
Proof. The receiver acceptance predicate also requires a TROPIC01 transfer witness, authenticated
TROPIC01 counter evidence, DSM transition proof, receiver challenge binding, boot ticket verification, and fused anchor head recomputation. A partition certificate alone cannot satisfy those
checks.
Theorem 34 (Replay Idempotence). Re emitting the same release package does not create a second
spend.
Proof. The same package has the same previous root, next root, transition digest, boot chain,
partition certificate, TROPIC witness, receiver challenge, fused anchor head, and counter evidence.
A receiver that already accepted it recognizes the same transition. Re emission is duplicate delivery,
not a distinct successor.
Theorem 35 (Recoverable Commit). If the counter moves for a release whose committed candidate
is durable, recovery either re emits the same release or downgrades to online recovery. It does not
sign a different release for the same counter step.
Proof. The recovery algorithm treats a committed record as a re emission obligation. If the committed flag is true and the record next anchor counter matches the live counter derived anchor counter,
recovery returns REEMIT COMMITTED. If the physical counter moved but the committed flag was
not durably written, then the record target anchor counter equals the live counter derived anchor
counter, so recovery marks the same record committed and returns REEMIT COMMITTED. If the
counter has not moved and the target anchor counter is the next physical step, recovery may move
the counter only after checking that the committed candidate previous root, bundle, and fused
anchor head still equal the active state. In no branch does recovery derive a new witness key or
sign a different release.
Theorem 36 (No Accepted Offline Bearer Double Spend). Under the stated assumptions, no
adversary can produce two distinct accepted offline bearer successors from the same spendable parent
except with negligible probability. If a conflicting branch is created outside the model, it is exposed
on reconciliation.
Proof. For a previous root hi
, the previous state commits to anchor bundle B, fused anchor head
Ai
, boot head Jb, and anchor counter ui
. An honest receiver accepts only a transition to hi+1
with next anchor counter ui + 1, valid DSM proof, valid boot ticket, valid partition certificate, valid
TROPIC witness, authenticated TROPIC01 counter evidence, valid fused anchor head update, and
next root commitment to the new fused anchor state.
A software clone cannot produce the partition and TROPIC evidence. A new hardware clone
cannot resume the committed boot head. A breached RP2350 alone cannot fake authenticated
TROPIC01 counter evidence. A broken TROPIC01 alone cannot fake the partition certificate,
DSM proof, boot ticket, and fused anchor head update. After one accepted counter commit, the
physical counter no longer supports a second accepted package from the same anchor counter. A
different successor from the same spendable parent is therefore rejected by the receiver predicate
or becomes a fork exposed by DSM reconciliation.
32 TLA+ Model
VARIABLES H, Active, CurrentRoot, step, delivered
25
LiveAnchorCounter == H0 - H
NextAnchorCounter == LiveAnchorCounter + 1
OfflineReady ==
/\ Active.root = CurrentRoot
/\ Active.anchor_counter = LiveAnchorCounter
/\ Active.status = "ready"
/\ Active.boot_valid = TRUE
/\ H > 0
/\ RMemoryMapOk
/\ FirmwareBoundaryOk
/\ LockoutOk
Boot ==
/\ step = "boot_required"
/\ BootWitnessGenerated
/\ PartitionBootCertValid
/\ Active’ = [Active EXCEPT !.boot_head = NextBootHead,
!.boot_valid = TRUE]
/\ step’ = "idle"
/\ UNCHANGED <<H, CurrentRoot, delivered>>
Prepare ==
/\ step = "idle"
/\ OfflineReady
/\ ReceiverChallengeFresh
/\ TransitionDigestOk
/\ PartitionCommitGenerated
/\ TropicWitnessGenerated
/\ PartitionFinalCertGenerated
/\ NextAnchorHeadComputed
/\ Active’ = [
root |-> Active.root,
anchor_bundle |-> Active.anchor_bundle,
anchor_head |-> Active.anchor_head,
boot_head |-> Active.boot_head,
anchor_counter |-> Active.anchor_counter,
boot_valid |-> Active.boot_valid,
status |-> "prepared",
record |-> [
prev_root |-> Active.root,
next_root |-> NextRoot,
prev_anchor_head |-> Active.anchor_head,
next_anchor_head |-> NextAnchorHead,
boot_head |-> Active.boot_head,
anchor_counter |-> LiveAnchorCounter,
next_anchor_counter |-> NextAnchorCounter,
challenge |-> ReceiverChallenge,
release |-> ReleasePkg,
committed |-> FALSE
]
]
/\ step’ = "prepared"
/\ UNCHANGED <<H, CurrentRoot, delivered>>
26
CommitStart ==
/\ step = "prepared"
/\ Active.status = "prepared"
/\ Active.record.prev_root = Active.root
/\ Active.record.prev_anchor_head = Active.anchor_head
/\ Active.anchor_counter = LiveAnchorCounter
/\ ReleaseDurable
/\ Active’ = [
root |-> Active.root,
anchor_bundle |-> Active.anchor_bundle,
anchor_head |-> Active.anchor_head,
boot_head |-> Active.boot_head,
anchor_counter |-> Active.anchor_counter,
boot_valid |-> Active.boot_valid,
status |-> "committed",
record |-> Active.record
]
/\ step’ = "commit_started"
/\ UNCHANGED <<H, CurrentRoot, delivered>>
CommitCounter ==
/\ step = "commit_started"
/\ Active.status = "committed"
/\ Active.record.committed = FALSE
/\ Active.record.next_anchor_counter = LiveAnchorCounter + 1
/\ Active.record.prev_root = Active.root
/\ Active.record.prev_anchor_head = Active.anchor_head
/\ H > 0
/\ H’ = H - 1
/\ Active’ = [Active EXCEPT !.record.committed = TRUE,
!.anchor_counter =
Active.record.next_anchor_counter]
/\ step’ = "committed"
/\ UNCHANGED <<CurrentRoot, delivered>>
Emit ==
/\ step = "committed"
/\ Active.status = "committed"
/\ Active.record.committed = TRUE
/\ Active.anchor_counter = LiveAnchorCounter
/\ delivered’ = delivered \cup {Active.record.release}
/\ step’ = "emitted"
/\ UNCHANGED <<H, Active, CurrentRoot>>
Finalize ==
/\ step \in {"committed", "emitted"}
/\ Active.status = "committed"
/\ Active.record.committed = TRUE
/\ Active.anchor_counter = LiveAnchorCounter
/\ Active’ = [
root |-> Active.record.next_root,
anchor_bundle |-> Active.anchor_bundle,
anchor_head |-> Active.record.next_anchor_head,
27
boot_head |-> Active.record.boot_head,
anchor_counter |-> Active.record.next_anchor_counter,
boot_valid |-> Active.boot_valid,
status |-> "ready",
record |-> EmptyRec
]
/\ CurrentRoot’ = Active.record.next_root
/\ step’ = "idle"
/\ UNCHANGED <<H, delivered>>
PowerLoss ==
/\ step’ = "recover"
/\ UNCHANGED <<H, Active, CurrentRoot, delivered>>
RecoverCommitted ==
/\ step = "recover"
/\ Active.status = "committed"
/\ Active.record.committed = TRUE
/\ Active.record.next_anchor_counter = LiveAnchorCounter
/\ delivered’ = delivered \cup {Active.record.release}
/\ Active’ = Active
/\ CurrentRoot’ = CurrentRoot
/\ step’ = "emitted"
/\ UNCHANGED H
RecoverCommitFlagLost ==
/\ step = "recover"
/\ Active.status = "committed"
/\ Active.record.committed = FALSE
/\ Active.record.next_anchor_counter = LiveAnchorCounter
/\ Active’ = [Active EXCEPT !.record.committed = TRUE,
!.anchor_counter =
Active.record.next_anchor_counter]
/\ delivered’ = delivered \cup {Active.record.release}
/\ CurrentRoot’ = CurrentRoot
/\ step’ = "emitted"
/\ UNCHANGED H
RecoverCommitNotMoved ==
/\ step = "recover"
/\ Active.status = "committed"
/\ Active.record.committed = FALSE
/\ Active.record.next_anchor_counter = LiveAnchorCounter + 1
/\ Active.record.prev_root = Active.root
/\ Active.record.prev_anchor_head = Active.anchor_head
/\ H > 0
/\ H’ = H - 1
/\ Active’ = [Active EXCEPT !.record.committed = TRUE,
!.anchor_counter =
Active.record.next_anchor_counter]
/\ delivered’ = delivered \cup {Active.record.release}
/\ CurrentRoot’ = CurrentRoot
/\ step’ = "emitted"
28
RecoverPrepared ==
/\ step = "recover"
/\ Active.status = "prepared"
/\ Active.anchor_counter = LiveAnchorCounter
/\ Active.record.prev_root = Active.root
/\ Active.record.prev_anchor_head = Active.anchor_head
/\ Active’ = Active
/\ delivered’ = delivered
/\ CurrentRoot’ = CurrentRoot
/\ step’ = "prepared"
/\ UNCHANGED H
RecoverIdle ==
/\ step = "recover"
/\ Active.status = "ready"
/\ Active.anchor_counter = LiveAnchorCounter
/\ Active’ = Active
/\ delivered’ = delivered
/\ CurrentRoot’ = CurrentRoot
/\ step’ = "idle"
/\ UNCHANGED H
OnlineAdvance ==
/\ step = "idle"
/\ CurrentRoot’ = OnlineSuccessor(CurrentRoot)
/\ step’ = "idle"
/\ UNCHANGED <<H, Active, delivered>>
Next ==
Boot
\/ Prepare
\/ CommitStart
\/ CommitCounter
\/ Emit
\/ Finalize
\/ PowerLoss
\/ RecoverCommitted
\/ RecoverCommitFlagLost
\/ RecoverCommitNotMoved
\/ RecoverPrepared
\/ RecoverIdle
\/ OnlineAdvance
The model obligations are:
Single active root.
The appliance has one active root and one active anchor counter.
One fused anchor head.
The active root commits to one fused anchor head.
Boot before offline.
Offline transfer is disabled unless a boot ticket or boot chain verifies from the DSM committed
boot head.
29
No export before commit.
A release is emitted only after the counter moves.
Replay is idempotent.
The same committed release may be re emitted without creating a new successor.
Prepared state blocks replacement.
A prepared record blocks another preparation from the same active root.
Recovery repeats the same successor.
Recovery emits the same committed successor. It does not sign a new one.
Finalize guard.
Finalize requires Active.u = H0 − H, equivalently Active.anchor counter = H0 − H.
Online separation.
If online state advances without the anchor, offline bearer mode is refused until resync.
33 Wire Protocol
The transport uses protocol buffers. The secure core exposes one entry point:
handle : bytes → bytes.
The host may relay packets, but receiver acceptance is based on public proofs, boot evidence,
partition evidence, fused anchor head verification, and authenticated TROPIC01 counter evidence.
Boot fencing is device internal. The host transport does not expose a callable boot operation, and
it does not accept host supplied boot sequence or firmware measurement fields.
syntax = "proto3";
package dsm.anchor;
message TransitionPackage {
bytes relationship_id = 1;
bytes object_id = 2;
bytes sender_device_id = 3;
bytes recipient_device_id = 4;
bytes prev_root = 5;
bytes next_root = 6;
uint64 anchor_counter = 7;
uint64 next_anchor_counter = 8;
uint32 action_type = 9;
bytes action_fields = 10;
bytes payload_hash = 11;
bytes old_leaf_proof = 12;
bytes new_leaf_proof = 13;
bytes authority_policy_hash = 14;
}
message BootTicket {
bytes anchor_bundle = 1;
bytes anchor_head = 2;
bytes prev_boot_head = 3;
30
bytes next_boot_head = 4;
uint64 boot_seq = 5;
bytes firmware_measurement = 6;
bytes partition_boot_signature = 7;
bytes tropic_boot_input = 8;
bytes tropic_boot_witness = 9;
}
message RootAdvanceCertificate {
bytes anchor_bundle = 1;
bytes prev_anchor_head = 2;
bytes next_anchor_head = 3;
bytes prev_boot_head = 4;
bytes current_boot_head = 5;
bytes prev_root = 6;
bytes next_root = 7;
uint64 anchor_counter = 8;
uint64 next_anchor_counter = 9;
bytes transition_digest = 10;
bytes root_advance_message = 11;
bytes partition_commitment = 12;
bytes tropic_transfer_input = 13;
bytes pk_hash = 14;
bytes pk_hw = 15;
bytes sigma_tropic = 16;
bytes sigma_partition = 17;
bytes anchor_id = 18;
uint32 transfer_slot = 19;
bytes receiver_challenge = 20;
}
message CounterEvidence {
bytes anchor_id = 1;
uint64 enrolled_counter = 2;
uint64 live_counter_claim = 3;
uint64 derived_anchor_counter_claim = 4;
bytes verifier_transcript = 5;
}
message OfflineRelease {
TransitionPackage transition = 1;
repeated BootTicket boot_chain = 2;
RootAdvanceCertificate cert = 3;
CounterEvidence counter = 4;
}
enum Op {
OP_UNSPECIFIED = 0;
OP_BOOT_RESERVED = 1;
OP_PREPARE = 2;
OP_COMMIT = 3;
OP_EMIT = 4;
OP_FINALIZE = 5;
OP_STATUS = 6;
31
OP_CANCEL = 7;
}
message ApplianceRequest {
Op op = 1;
TransitionPackage transition = 2;
bytes receiver_challenge = 3;
reserved 4, 5;
}
message ApplianceResponse {
Op op = 1;
bool ok = 2;
uint32 error = 3;
OfflineRelease release = 4;
bytes active_root = 5;
bytes anchor_bundle = 6;
bytes active_anchor_head = 7;
bytes active_boot_head = 8;
uint64 active_anchor_counter = 9;
uint32 status = 10;
}
The field name OP BOOT RESERVED is deliberate. The value is reserved so old host driven boot
semantics do not reappear. ApplianceRequest fields 4 and 5 are also reserved. They must not
be reused for host supplied boot seq or firmware measurement. Those values are device internal
boot data recorded in the BootTicket.
The partition commitment in RootAdvanceCertificate is recomputed from B, Ai
, Jb
′, and
Mi+1 only. It does not carry and does not hash a partition epoch or partition nonce.
The fields live counter claim and derived anchor counter claim are transport claims. They
are not accepted as proof. The receiver verifier must parse or obtain an authenticated TROPIC01
value from verifier transcript, or through another policy approved authenticated counter evidence path.
The signature fields sigma tropic and sigma partition are variable length. Whenever either
signature is bound into another digest, the implementation uses SigCommit(σ), not raw concatenation and not a bare H(σ).
34 Reference Implementation
The reference implementation has three visible parts:
• crates/dsm-anchor-core, the Rust protocol core;
• crates/dsm-anchor-pico, the firmware target;
• the DSM SDK receiver adapter that routes offline bearer acceptance through the anchor
predicate.
The protocol core implements:
• canonical encodings;
32
• anchor bundle construction;
• birth fuse commitment;
• boot ticket verification;
• root advance digest construction;
• partition commitment construction without partition epoch or partition nonce;
• TROPIC01 witness input construction;
• wots witness signatures;
• BLAKE3-SPHINCS+ SPX128f partition signature handling;
• fixed width SigCommit(σ) binding for variable length signatures;
• partition certificate verification;
• fused anchor head construction;
• public receiver acceptance;
• recovery;
• protocol buffer wire encoding.
The firmware target is the Rust dsm-anchor-pico crate. It drives TROPIC01 through libtropic-rs
bindings over SPI at 3.3 V under an authenticated L3 session. The protocol does not require a missing C firmware layer. The RP2350 code is a transport and partition state machine layer. Receiver
acceptance is not based on trusting RP2350 statements.
Boot fencing is performed by the device. The host operation value formerly used for boot is
reserved. The host does not provide the boot sequence or firmware measurement used by the boot
ratchet.
The receiver acceptance implementation separates the counter evidence parser from the release
fields. The counter verifier returns the authenticated counter value obtained from TROPIC01, and
the acceptance predicate compares that value to the expected H0 − (ui + 1).
Verifier trait names should follow the same semantics:
• prev root commits anchor state;
• verify transition(prev root, next root, ...);
• verify boot chain;
• verify partition certificate;
• read authentic counter;
• next root commits anchor state.
33
35 Implementation Status
The host side appliance state machine, fused root advance, receiver predicate, canonical wire validation, and Pico firmware target are implemented in the reference code. Host tests are green for
the implemented anchor core behavior.
Receiver side offline bearer acceptance is intentionally fail closed until the Phase 5 producer
inputs are present. The sender side must carry an OfflineRelease on transfer confirmation, the
counter evidence path must supply a usable authenticated verifier transcript, and the DSM SMT
leaf must commit the anchor tuple:
(B, Ai
, Jb, ui).
Until those inputs exist together, the receiver adapter routes offline bearer transfers to online
checked recovery rather than accepting offline bearer mode.
Device side durable recovery is specified by the protocol and implemented in host logic, but it
is not yet a hardware backed cross power cycle property unless Active is persisted in TROPIC01
R memory. A firmware build that keeps Active in RAM and re enrolls on boot is an early bringup
build, not a complete hardware backed recovery implementation.
Firmware measurement is specified by the protocol, but a fixed test constant is only a bringup
stub. A production measured boot claim requires replacing that constant with a real measurement
of firmware and policy state.
The TLA+ model in this paper is the boot fenced fused anchor model. It should exist in the
repository as tla/DSM BootFencedFusedAnchor.tla. Older offline finality or Tripwire models do
not replace this model because they use different variables and prove a different machine.
36 Validation Plan
T1. Hardware bringup.
Connect Raspberry Pi Pico 2 W to Secure Tropic Click over SPI at 3.3 V and confirm
TROPIC01 communication.
T2. TROPIC identity.
Read chip identity and bind anchor id to the authority policy.
T3. Secure session.
Establish authenticated L3and confirm encrypted communication.
T4. Birth fuse.
Generate sbirth, derive B, A0, J0, p0, destroy sbirth, and verify public enrollment data cannot
recreate p0.
T5. Boot ticket.
Produce a boot ticket from the partition boot ratchet and TROPIC01 boot MACANDD slot.
Expected result: offline bearer mode is disabled until the ticket verifies.
T6. New hardware resume.
Copy host state to a different RP2350/TROPIC01 pair. Expected result: boot ticket cannot
be chained from the committed boot head under the enrolled bundle.
T7. Counter direction.
Initialize counter at H0, update it, and confirm u = H0 − H increases by one.
34
T8. Counter evidence.
Have the receiver act as verifier endpoint and read the live counter through an authenticated
L3session.
T9. MACANDD transfer witness.
Run MACANDD on the fused transfer input and derive a witness key.
T10. Public witness verification.
Produce a release and verify the TROPIC witness signature under the public acceptance predicate.
T11. Partition cross binding.
Mutate the partition commitment, TROPIC witness, or partition final certificate. Expected
result: receiver rejects.
T12. DSM proof verification.
Mutate old leaf proof, new leaf proof, recipient, payload, object, previous root, or next root.
Expected result: receiver rejects.
T13. Fused anchor head verification.
Mutate Ai
, Ai+1, Jb, or Jb
′. Expected result: receiver rejects.
T14. Counter mismatch.
Attempt to reuse the same previous root after one counter commit. Expected result: receiver rejects because the previous state committed anchor counter and authenticated TROPIC counter
evidence do not match.
T15. RP2350 breach simulation.
Feed arbitrary next roots, wrong previous roots, stale anchor counters, forged boot heads, and
forged status outputs. Expected result: receiver rejects unless DSM proof, partition evidence,
TROPIC witness, counter evidence, and fused anchor head are valid.
T16. Counter trust seam.
Create a release with a forged host supplied counter claim but a transcript attested counter
value that does not match. Expected result: receiver rejects. The accepted value is the
authenticated TROPIC01 value, not the host claim.
T17. Power loss after boot ticket.
Cut power after boot ticket generation. Expected result: boot chain either verifies or offline
mode remains disabled.
T18. Power loss after prepared.
Cut power after prepared record is durable. Expected result: complete the same record, cancel
it, or route online. Do not create a second record from the same active root.
T19. Power loss after release durable before counter commit.
Cut power after the committed candidate is durable but before the counter moves. Expected
result: recovery may commit the same release only if the candidate previous root and fused
anchor state still equal the active state.
T20. Power loss after counter moved before commit flag.
Cut power after the physical counter moves but before the committed flag is durable. Expected
35
result: recovery marks the same candidate committed, does not move the counter again, and
re emits the same release.
T21. Replay.
Emit the same release twice. Expected result: duplicate delivery of the same successor.
T22. Online stale.
Advance DSM online without the anchor. Expected result: offline bearer mode refused until
resync.
T23. Physical compromise policy.
Mark anchor physically suspect. Expected result: offline mode suspended and authority rotation required.
37 Validation Results on Target Hardware
The prior hardware bringup exercised the target stack:
Stage Result Meaning
Chip identity TROPIC01 identity read; silicon revision ACAB anchor can be pinned
Secure session X25519 handshake, encrypted L3, echo and TRNG checked authenticated commandCounter counter initialized at H0 = 1000, updated to H = 997 u = H0 − H advances
MACANDD reproducible witness after rearm, distinct output without rearm stateful witness behavioWitness flow MACANDD → K → wots, 32 byte public key, 2144 byte signature public witness path worCore acceptance release verified and successor frontier matched in host validation public predicate acceptsUSB host external host drove status and offer flow over USB CDC appliance can be drivenFor this boot fenced fused anchor version, the remaining activation work is focused on sender
side OfflineRelease transport, receiver authenticated counter transcript support, DSM SMT commitment of B, Ai
, Jb, ui
, TROPIC01 R memory backed durable Active persistence, and replacement
of the firmware measurement test constant with a real measurement.
38 Security Summary
36
Part Provides Does not provide
Birth fuse non recreatable enrollment preimage live clone detection by itself
Anchor bundle immutable hardware and policy binding forward motion by itself
Boot ticket new hardware resume resistance DSM validity
Previous DSM root object state and expected fused anchor state hardware presence
Receiver challenge freshness and recipient binding uniqueness by itself
DSM transition proof valid root update hardware presence
RP2350 partition cert appliance partition lineage DSM validity by itself
TROPIC01 MACANDD enrolled hardware witness DSM validity
TROPIC01 counter evidence exact next physical counter state recipient binding
Fused anchor head binds DSM, partition, and TROPIC lineage value validity by itself
RP2350 host path transport and local state machine trusted receiver facts
Recovery record no orphaned committed release new authority by itself
Tripwire fork exposure on reconciliation instant awareness
cryptographic security
39 Limits
(1) Perfect live state emulation is outside offline distinguishability. If an attacker extracts
and perfectly emulates the exact current non exportable state of the partition, TROPIC01,
and DSM authority state, no offline-only protocol can distinguish that from the original.
(2) TROPIC01 physical extraction alone is not sufficient, but it is serious. If the secure
element is physically broken, offline bearer mode should be suspended and authority rotation
should occur unless policy explicitly allows continued risk.
(3) RP2350 breach can still cause denial of service. A breached RP2350 can waste counter
steps, corrupt local state, or force online recovery.
(4) Boot fencing is load bearing for new hardware rejection. A copied state image must
not be allowed to produce offline releases unless it first proves a boot chain from the committed
boot head.
(5) Receiver counter evidence is load bearing. The receiver must not accept host reported
counter state.
(6) DSM proof verification is load bearing. The receiver must verify hi → hi+1. A hardware
certificate over an invalid root does not create value.
(7) Recovery durability is load bearing for liveness. If the counter moved, the same release
must remain recoverable. Otherwise the appliance risks an orphaned commit, which is a
liveness failure.
(8) New relationships remain online checked. A closed adversary branch does not affect
honest parties because independent relationships and reconciliation require valid root lineage
and counter evidence.
(9) Tripwire exposes later. Tripwire exposes forks on reconciliation.
37
40 Conclusion
The boot fenced fused anchor authority is the compact form of the DSM offline bearer appliance.
It does not need a large precommit table. It does not need separate offered, pending, armed,
and released protocol names. The load bearing object is the fused transition:
(hi
, Ai
, Jb, ui) → (hi+1, Ai+1, Jb
′, ui + 1).
The previous DSM root commits to the anchor bundle, fused anchor head, boot head, and anchor
counter. The receiver verifies the DSM transition to hi+1. The receiver challenge binds the release to
the actual counterparty. The RP2350 partition certificate proves the partition lineage participated.
TROPIC01 MACANDD proves enrolled hardware witness participation. Authenticated TROPIC01
counter evidence proves the physical counter corresponds to the exact next anchor counter. The
fused anchor head binds these into a single non interchangeable lineage.
TROPIC01 is necessary but not sufficient. The RP2350 partition is necessary but not sufficient.
DSM validity remains public and receiver verified.
A copied state image cannot resume offline bearer mode on new hardware because offline release
requires a boot ticket chained from the DSM committed boot head under the enrolled anchor bundle.
New hardware requires online authority rotation.
If RP2350 is breached, the attacker can brick the appliance or force online recovery, but cannot
make an honest receiver accept an invalid root transition or a second valid successor from the
same spendable parent without also satisfying DSM verification, boot evidence, partition evidence,
authenticated TROPIC01 counter evidence, and fused anchor head verification.
If the counter moves, the same release must remain recoverable. Recovery therefore re emits
the same committed release and finalization is guarded by the live counter derived anchor counter.
The whole design reduces to one sentence:
The receiver accepts only a publicly valid DSM root advance whose boot ticket, partition certificate, TROPIC01References
[1] Cryptskii. DSM: Deterministic State Machines. Irrefutable Labs Inc., 2026.
[2] Tropic Square. TROPIC01 Datasheet, API, Application Notes, and Libtropic Documentation.
Manufacturer documentation.
[3] Tropic Square. TROPIC01 PIN Verification Application Note. ODN TR01 app 002, Version
1.2, 2026.
[4] Johannes Buchmann, Erik Dahmen, Sarah Ereth, Andreas H¨ulsing, and Markus R¨uckert. On
the Security of the Winternitz One Time Signature Scheme. AFRICACRYPT 2011.
[5] Leslie Lamport. Specifying Systems: The TLA plus Language and Tools for Hardware and
Software Engineers. Addison Wesley, 2002.
38