---
applyTo: '**'
---
Software Authority, Hardware Identity
Brandon Ramsay
Irrefutable Labs Inc.
July 2026
Abstract
A Deterministic State Machine, or DSM, advances state by local deterministic acceptance
rather than by global consensus. Ordinary DSM operation does not require a blockchain,
validator set, sequencer, wall clock, or online settlement step on the common path.
This paper replaces the previous offline bearer specification. The previous specification
treated a hardware monotonic counter as the transfer uniqueness authority and built a receiver witnessed counter positioned commit around it. Adversarial review showed that a
scalar counter read never binds the transition it brackets, and further review showed that
the binding was never needed. Transfer uniqueness is already a software property of DSM:
the device state is one resource, it is consumed as a whole, and one parent state admits
exactly one accepted successor. Hardware cannot add to that property. Hardware can only
get in its way. This paper states and proves the exclusion as a software only theorem: no
step of the proof reads hardware state, and deleting every hardware component of the design
leaves the theorem intact.
The remaining, irreducible job of hardware is device identity. A software clone holds every
byte of host state. Software alone cannot distinguish the clone from the original. This paper
therefore assigns hardware exactly one role: making device identity physically unclonable,
and bounding offline exposure while doing it.
The design has two permanent identity domains on one device. The online domain derives
its identity from a BIP39 seed alone. It requires no hardware, costs nothing beyond a phone,
and supports all online DSM operation. The offline domain derives its identity from a fusion
of three factors: the BIP39 seed held on the phone, a PUF rooted non exportable key inside
a TROPIC01 secure element, and a partition sealed key inside the RP2350 secure partition.
Every offline bearer release must be witnessed by all three factors. Compromise of any one
factor, or any two, does not yield the offline identity. A device may operate online only for its
entire life, or add the offline domain later by an appliance birth ceremony. Neither domain
is legacy. Both are permanent.
The design adds one structural element to the DSM device state: a monotone counter
committed as a leaf of the device sparse Merkle tree. The SMT counter makes state position
explicit, is consumed with the whole state, decides staleness on sight, and is the software
register the TROPIC01 monotonic counter must track one to one, one physical decrement
per offline commit. The physical counter is not an acceptance authority. It is a tracker of
the SMT counter: a non rewind floor, a stale image tripwire, and an offline exposure cap.
The receiver witnessed counter positioned commit, the MACANDD transfer witness, the
fused anchor head, the boot ticket chain, and the first transfer disclosure round trip of the
previous specification are removed. The July 8, 2026 silicon validation on Raspberry Pi
Pico 2 W with TROPIC01 is retained and reinterpreted under the new claims: it validates
counter initialization, single commit discipline, refusal of a second commit, counter stability,
and distinct per die chip identity across two physical chips.
1
1 Purpose and Scope
This document specifies the DSM device identity and offline bearer authority. It replaces the
specification titled Boot Fenced Fused Anchor Authority for DSM Offline Bearer State in full.
Section 24 enumerates what was removed and why.
The central claim of this document is a separation:
Software (DSM) enforces correctness and uniqueness of state transitions.
Hardware (anchor) enforces uniqueness of the physical device instance.
These two jobs are not mixed. The hardware never authorizes a transaction. The software
never attempts to prove physical possession.
The authority provides:
1. one online device identity derived from a BIP39 seed, requiring no hardware;
2. one offline device identity derived from a three factor fusion of seed, PUF rooted chip key,
and partition sealed host key;
3. a permanent dual domain structure in which both identities coexist on one device;
4. an upgrade ceremony by which an online only device gains the offline domain;
5. transfer uniqueness enforced entirely in software by whole state consumption, stated and
proved with no hardware term (Theorem 1, Corollary 1);
6. a monotone state counter committed in the device SMT, making position explicit, staleness
decidable on sight, and hardware synchronization definable (Section 8);
7. a three factor release witness on every offline bearer transfer;
8. a physical counter synchronized one to one to the SMT counter, providing a non rewind
floor and an offline exposure cap;
9. recovery by re emitting the same committed release;
10. Tripwire exposure of any fork on reconciliation, and bricking of split identities on first
honest contact.
The target hardware for the offline domain is unchanged:
Layer Part Role
Controller Raspberry Pi Pico 2 W host and transport board
MCU RP2350 secure partition, host key, appliance policy
Secure element board MIKROE 6559 Secure Tropic Click TROPIC01 over SPI
Secure element TROPIC01 PUF rooted chip key, monotonic counter
Interface SPI at 3.3 V secure element command transport
The online domain requires none of it.
2
2 Trust Decomposition
Every component is assigned exactly one job. No component is trusted for a job assigned to
another.
Component Provides
DSM / device SMT transition validity; transfer uniqueness by whole state
consumption; one parent, one accepted successor
BIP39 seed (phone) online identity; factor one of the offline identity
PUF chip key
(TROPIC01)
factor two; per release hardware witness; unclonable per
die
Partition key (RP2350) factor three; per release host witness
Monotonic counter non rewind floor; stale image bricking; offline exposure
cap
Tripwire fork exposure at reconciliation; identity split bricking
Explicit non goals for hardware: ordering, transaction uniqueness, transaction authority,
double spend prevention. The previous specification assigned all four to hardware. All four are
removed.
3 Naming Discipline
The protocol uses the following names. These names are not interchangeable.
Name Meaning
Ri sender device SMT root before transfer
Ri+1 sender device SMT root after transfer
hi offline frontier root advanced from
hi+1 offline frontier root advanced to
ℓi relationship leaf or chain head inside the sender SMT
κres concrete resource occurrence consumed by the transfer
ui anchor counter coordinate committed in Ri
H0 enrolled TROPIC01 physical counter value
H live raw TROPIC01 physical counter value
B immutable enrollment bundle (offline domain)
Ion online device identity
Ioff offline device identity
Di+1 transition digest
Mi+1 root advance message
rR receiver challenge
The device root is the per device SMT root. The offline frontier root hi
is a dedicated forward
only lineage advanced exactly once per offline bearer transfer; it is the object a counterparty
tracks. The relationship leaf is the bilateral chain head inside the device SMT. Each bilateral
relationship is its own independent straight hash chain with exactly one receiver.
3
The anchor counter is not the raw TROPIC01 counter. The anchor counter increases:
u = H0 − H.
The raw TROPIC01 counter counts down: H ← H − 1. All subtraction is checked; H > H0 is
rejected as counter mismatch.
4 Cryptographic Preliminaries
Let H denote BLAKE3 256, modeled as collision resistant and second preimage resistant. Let
HKDF denote a domain separated key derivation function. All structured objects use canonical
byte encoding; verifiers reject non canonical encodings. If X is structured, enc(X) is its canonical
encoding.
Three signature schemes appear.
1. (DsmSign, DsmVerify): the DSM device signature scheme (the production post quantum
suite). Device keys are derived from the seed. Every DSM transition is signed under this
scheme; this is factor one.
2. (ChipSign, ChipVerify): Ed25519 executed inside TROPIC01 under a resident, non exportable key pair generated in slot at birth. Key storage inside TROPIC01 is protected
by the die’s physically unclonable function. This is factor two.
3. (HostSign, HostVerify): a signature scheme under a key pair generated inside the RP2350
secure partition at birth and sealed to it. This is factor three.
The previous specification derived a one time witness key from a MACANDD output. That
construction is removed. The reason is recorded here because it is load bearing for the design: the
MACANDD slot state is a pure function of the call input and the slot index. The vendor’s own
reference PIN flow restores consumed slots by replaying a known input. Slot state is therefore
host restorable and carries no forward only lineage. A resident non exportable signing key is the
correct possession witness; its signatures are portable and verifiable offline by any receiver with
no relay session to the chip.
5 Identity Domains
The device carries two identities in two hash separated domains. Both are permanent. Relationships are tagged by domain at establishment and never migrate.
5.1 Online Identity
Let seed be the BIP39 derived master secret held on the phone. The online root secret is
kon = HKDF(seed, "DSM/identity/online/v1"),
4
from which the DSM device key pair (skon, pkon) is derived. The online identity is
Ion = H("DSM/identity/online-id/v1" ∥ pkon).
The online domain requires no hardware anchor. All online DSM operation, including relationship establishment, bilateral transfer, and reconciliation, proceeds under Ion with DSM
signatures alone.
5.2 Offline Identity
The offline identity exists only after an appliance birth (Section 6) and is the hash of the anchor
bundle:
Ioff = H("DSM/identity/offline-id/v1" ∥ B).
The bundle B binds all three factors (Section 7). Producing a valid offline bearer release requires
live cooperation of all three: the DSM transition is signed under seed derived keys, and the release
certificate carries both the chip signature and the host signature over the same root advance
message.
5.3 Upgrade Ceremony
A device operating online only may add the offline domain at any time. The ceremony is:
perform appliance birth, obtain B, and publish an upgrade certificate
U =

B, σon
, σon = DsmSign
skon, H("DSM/identity/upgrade/v1" ∥ B)

.
The certificate binds Ioff to Ion under the online identity’s own signature. Counterparties that
have themselves upgraded may then establish offline domain relationships with the device. Existing online relationships continue unchanged. Neither domain is legacy; the device uses each
domain with counterparties who operate in it.
5.4 Compromise Matrix
Attacker holds Online domain Offline domain
phone (seed) only takeover safe (lacks chip, host)
chip only safe safe (lacks seed, host)
host (RP2350) only safe safe (lacks seed, chip)
phone + chip takeover safe (lacks host)
phone + host takeover safe (lacks chip)
chip + host safe safe (lacks seed)
phone + chip + host takeover takeover (full compromise)
The online domain is deliberately one factor: it is the zero hardware entry path. Value held
in offline domain relationships is protected by the full fusion. A user may keep the phone, the
appliance, and the seed backup physically separate; the offline domain then survives the loss or
compromise of any one of them, and of any two.
5
6 One Way Birth Fuse
Definition 1 (One Way Birth Fuse). The one way birth fuse sbirth is a secret enrollment preimage formed from RP2350 partition entropy, TROPIC01 birth witness material, host entropy,
the online identity commitment, device context, and authority policy. Public enrollment objects
commit only to H(sbirth). The preimage is destroyed immediately after deriving the initial private
state.
At birth, the appliance derives
sbirth = H

"DSM/anchor/birth-secret/v2" ∥ trngP ∥ witT ∥ noncehost ∥ H(pkon) ∥ device id ∥ policy hash
,
publishes Sbirth = H(sbirth), derives the initial partition seal
p0 = HKDF
sbirth, "DSM/partition-seal/v2" ∥ B

,
and destroys sbirth ← ⊥. The partition key pair is generated under the seal. The chip witness
key pair is generated in slot inside TROPIC01 with the non exportable flag set; its at rest
protection is the die PUF.
Remark 1. The enrolled counter value H0 is not destroyed. Counterparties and auditors need
H0 to evaluate u = H0 − H. The destroyed value is the birth preimage, not H0.
7 Anchor Bundle and Counter Birth
Definition 2 (Anchor Bundle). The anchor bundle B is the immutable enrollment digest of the
offline domain:
B = H

"DSM/anchor-bundle/v2" ∥ H(pkon) ∥ stpub ∥ pkchip ∥ pkhost ∥ le64(H0) ∥ device id ∥ policy hash ∥ Sbirth
.
Here stpub is the chip’s static per die public identity, unique to the physical die and rooted
in its PUF, and pkchip is the resident witness verification key. Offline bearer releases under a
different bundle are not valid successors of state committed to B.
Counter birth is part of enrollment. On a production fresh chip the monotonic counter is
initialized to the maximum value; that value is the enrolled H0 and is bound into B. Because B
is immutable and committed in the device SMT from genesis of the offline domain, H0 cannot
be silently re enrolled: a re initialized counter under a new H0 is a new bundle, a new Ioff,
and a fresh identity with no claim to the old lineage. Implementations must additionally lock
the counter initialization capability at provisioning where the hardware supports it, so that re
initialization requires visible re birth rather than a host call.
8 The SMT State Counter
The offline domain adds exactly one structural element to the base DSM device state: a monotone counter committed as a leaf of the device sparse Merkle tree. The addition is required, not
decorative. Without a committed counter, the position of a state is implicit in its root history,
staleness is decidable only by chain comparison, and the hardware synchronization of Section 11
is not even definable. With it, position is a scalar inside the root, and the root consumes it.
6
8.1 Placement and Birth Embedding
The birth is embedded in the tree. The counter leaf is keyed by the anchor bundle B, which
commits Sbirth and H0; the counter starts at that leaf, at zero, when the offline domain is born,
and advances by exactly one per offline bearer commit, atomically with the relationship advance,
under the same root replacement.
Definition 3 (Anchor State Leaf). The anchor state leaf is the device SMT leaf keyed by the
anchor bundle whose value commits the offline domain position:
Li = H

"DSM/anchor-state/v2" ∥ B ∥ hi ∥ le64(ui)

.
Definition 4 (Offline Frontier Root). The offline frontier root is a dedicated forward only hash
lineage advanced exactly once per offline bearer transfer:
hi+1 = H

"DSM/anchor-root-advance/v2" ∥ hi ∥ Di+1
,
seeded at birth by h0. It is the object a counterparty durably tracks for the holder.
8.2 What the Committed Counter Provides
1. Explicit position. ui
is the coordinate of the sender state, proven to any receiver by an
SMT inclusion proof against Ri
. Position is not inferred from history. It is read from the
state.
2. Consumption with the whole state. The counter lives inside the root. Advancing it is
not a side effect of a transfer; it is part of the single root replacement that is the transfer.
A parent root therefore admits exactly one indexed successor, at position ui + 1: the index
cannot advance without the state, and the state cannot advance without the index.
3. Staleness on sight. Against any known later frontier, an older state is exposed by a
scalar comparison of committed counters. No chain walk and no reconciliation round is
required to reject a stale image.
4. Fork comparability. Two successors of one origin necessarily collide at position ui + 1
(Lemma 3). A fork is a decidable leaf collision, not a divergence that must be discovered
by replaying histories.
5. The hardware synchronization target. The physical counter of Section 11 is meaningful only because there is a committed software register for it to track. The invariant
u = H0 − H is a statement about this leaf.
8.3 Counter Synchronized State
Definition 5 (Counter Synchronized State). The appliance state is counter synchronized when
ui = H0 − H holds for the committed ui and the live raw counter H, outside of an in flight
commit. Every offline commit advances both by exactly one, atomically with the relationship
advance and the anchor leaf update.
Online transfers do not touch the counter leaf, the frontier root, or the hardware counter.
The SMT counter counts offline bearer commits only; base DSM online operation needs no
counter for uniqueness, as Section 9 proves.
7
9 Software Only Double Spend Exclusion
This section states the property the previous specification tried to buy from hardware, and
proves that software already owned it. Every object examined here — roots, leaves, chains,
counter positions, signatures — is software state.
Definition 6 (Whole State Consumption). A DSM device state is a single resource. An accepted
transfer consumes the parent device root Ri entirely and yields exactly one successor Ri+1. There
is no partial advance. The relationship leaf, the object leaves, and (for offline transfers) the
anchor state leaf move together under one root replacement.
Definition 7 (Offline Origin). The offline origin of a transfer is the tuple (Ri
, hi
, ui): the sender
device root, the offline frontier root, and the anchor counter coordinate committed by the anchor
state leaf of Ri.
Definition 8 (Double Spend). A double spend exists if two distinct transitions consume the same
origin and the same resource occurrence κres, and both satisfy the offline acceptance predicate at
honest receivers.
Across relationships, distinct relationships consume distinct occurrences; committing the
same κres into two relationship advances requires two successors of one device root, which is
exactly the case the following lemmas and theorem dispose of.
Lemma 1 (Root Singularity). At any honest receiver, at most one successor of a given parent
frontier is accepted.
Proof. Acceptance persists the successor frontier hi+1 for the holder before value is treated as
received. A later release claiming previous frontier hi no longer matches the adopted frontier,
and cannot repair the mismatch with a Branch Proof: a verifying hop chain from hi+1 back to
hi would close a cycle hi → hi+1 → · · · → hi
in a forward only hash lineage, which yields a
collision in H.
Lemma 2 (Straight Bilateral Chains). Within a bilateral relationship, “same parent, two receivers” is unconstructible: the relationship is an independent straight hash chain with exactly
one receiver and one tip, and the tip is consumed by the advance.
Proof. The relationship leaf commits the chain tip. An advance replaces that tip under the
same leaf key inside the root replacement that is the transfer. Two advances of one tip are
two successors of one parent root, both addressed to the chain’s single receiver, of which that
receiver accepts at most one by Lemma 1.
Lemma 3 (Position Collision). Any two distinct successors of one origin (Ri
, hi
, ui) commit
the same counter position ui + 1 at the same leaf key under different roots. The fork is therefore
decidable by comparing the two leaves, by any party holding both releases, with no reconciliation
round. In addition, and beyond what Theorem 1 requires: the live enrolled chip carries a single
counter value, so as either lineage advances, at most one branch remains synchronized with it,
and any authenticated audit read exposes the other as stale.
8
Proof. Acceptance requires the successor anchor leaf to commit exactly ui + 1 by checked arithmetic. Two distinct successors present (B, h′
, ui+1) and (B, h′′, ui+1) with h
′ ̸= h
′′: two claims
to one position under one bundle, decided by direct leaf comparison. The supplementary clause
follows from monotonicity of the physical counter and Definition 5.
Theorem 1 (Software Only Double Spend Exclusion). For every adversary, up to and including
full stack compromise: (i) no honest receiver accepts two successors of one origin; (ii) within a
bilateral relationship, no fork is constructible at all; (iii) if two honest receivers accept divergent
successors of one origin, the two releases form a decidable position collision, the fork is exposed
at first comparison or reconciliation, and both lineages are refused thereafter. No step of this
proof reads hardware state.
Proof. (i) is Lemma 1. (ii) is Lemma 2. For (iii): divergent acceptance requires two distinct
root replacements of one parent, each carrying a valid DSM transition signed under the holder’s
own device keys; only the holder’s authority produces such a pair, which in the offline domain
is the full stack adversary of Section 16. By Lemma 3 the pair is a position collision decidable
on sight by any party holding both releases; by Assumption 1 the conflicting tips cannot survive reconciliation; honest counterparties then refuse both lineages (Theorem 6). Every object
examined — adopted frontiers, SMT leaves, committed counter positions, hash chains, DSM
signatures — is software state.
Corollary 1 (Hardware Independence). Delete every hardware component of this specification
— the secure element, the host partition, the physical counter — and Theorem 1 holds unchanged.
Hardware serves device identity (Theorem 3) and offline exposure bounding (Section 11). It
contributes nothing to transfer uniqueness, and the previous specification’s attempt to make it
contribute was the source of that specification’s complexity.
That is the separation of Section 2, proved rather than asserted.
10 Three Factor Release Witness
Let ∆◦
i+1 be the canonical transition core: action, recipient identity, object identifier, payload,
old state proofs from Ri
, the counter pair (ui
, ui+1), and the receiver challenge rR. The core
deliberately excludes the successor root. The transition digest is
Di+1 = H

"DSM/transition-digest/v2" ∥ enc(∆◦
i+1)

.
The dependency order is a clean DAG:
Di+1 → hi+1 → Li+1 → Ri+1 → Mi+1 → σ
chip
i+1 , σhost
i+1 .
The root advance message binds both roots on each side:
Mi+1 = H

"DSM/root-advance/v2" ∥ B ∥ Ri ∥ Ri+1 ∥ hi ∥ hi+1 ∥ le64(ui) ∥ le64(ui+1) ∥ Di+1 ∥ recipient ∥ rR

.
The witnesses are
σ
chip
i+1 = ChipSign(Mi+1), σhost
i+1 = HostSign(Mi+1).
9
Factor one is the DSM transition itself: ∆◦
i+1 is signed under seed derived DSM device keys per
ordinary DSM rules. A release therefore proves live cooperation of phone, chip, and host over
this exact transition, this exact recipient, and this exact challenge.
Definition 9 (Release Certificate and Package).
Certi+1 =

B, Ri
, Ri+1, hi
, hi+1, ui
, ui+1, Di+1, Mi+1, σ
chip
i+1 , σhost
i+1 , rR

,
Pkgi+1 =

∆◦
i+1, Πi
, Πi+1, Certi+1, BranchProof [optional]
,
where Πi
, Πi+1 are the SMT inclusion proofs for the anchor state leaf in Ri and Ri+1 and for
the relationship advance.
Definition 10 (Branch Proof). When the receiver’s stored frontier for the holder is hk with
k < i, the release carries the ordered hop certificates for hk → · · · → hi, each hop being a prior
Cert whose σ
chip and σ
host verify and whose roots chain. The receiver advances its frontier along
the sender’s own witnessed lineage. Interleaved counterparties therefore do not require online re
admission.
11 Synchronized Anchor Counter
The authoritative register is the SMT counter of Section 8: committed position, consumed with
the state. This section specifies the physical tracker bound to it. The physical counter has three
jobs. None of them is acceptance authority.
1. Non rewind floor. The hardware counter is monotonic and non resettable under the
enrolled H0. A device image restored to an older state carries an anchor leaf with u < H0−
H. The appliance refuses to operate on it (recovery, Section 14), and any authenticated
audit read exposes it.
2. Stale image and split bricking. Of two divergent lineages claiming the same identity,
at most one is counter consistent with the live chip. Reconciliation or any authenticated
read distinguishes them; the inconsistent lineage is bricked.
3. Offline exposure cap. Policy bounds u−urec ≤ W, where urec is the counter coordinate
at the holder’s last reconciliation and W is the policy window bound into policy hash.
Lifetime capacity is bounded by H0 (about 232), the exposure cap, and flash wear.
Commit discipline: prepare moves nothing; commit performs exactly one counter update
after re pinning H0 − H = ui with checked arithmetic; H = 0 returns EXHAUSTED ONLINE ONLY;
a second commit against the same prepared transition is refused. This discipline is exactly what
the July 8, 2026 silicon run executed (Section 23).
A receiver may, when in physical proximity and when policy demands it for high value
acceptance, open an authenticated session to the enrolled chip and read H as an audit cross
check of Definition 5. This verify live mode is optional. The acceptance predicate does not
require it, because a scalar counter read never binds the transition it brackets; the binding work
is done by the three signatures over Mi+1.
10
12 Offline Transfer Protocol
The appliance has three transfer states: Ready, Prepared, Committed. Offline bearer mode is
enabled only when the firmware measurement matches enrolled policy; this gate is an implementation requirement, not a cryptographic object of the protocol.
12.1 Prepare
The receiver checks the proposed transfer at the human and DSM level and supplies a fresh
challenge rR
$←− {0, 1}
256. The appliance checks status = Ready, checks counter synchronization
ui = H0 −H, constructs ∆◦
i+1, Di+1, hi+1, Li+1, Ri+1, Mi+1, obtains σ
chip
i+1 and σ
host
i+1 , and writes
a durable prepared record. No counter has moved. No release has been exported. Exactly one
prepared record may exist per frontier.
12.2 Commit
The appliance stores the committed candidate durably with counter committed = false, re pins
H0 − H = ui
, and if the check holds and H > 0, issues the single counter update H ← H − 1,
marks counter committed = true, and erases transient signing material. If the re pin fails, the
operation downgrades to online recovery without moving the counter.
12.3 Emit and Finalize
The appliance exports Pkgi+1 only after the counter commit. Finalization requires Active.u+1 =
H0 − H and writes the successor active state. If power fails before finalize, recovery re emits the
same committed release and finalizes the same successor.
12.4 First Transfer Offline
A first transfer to a new counterparty requires no special round trip. The receiver supplies rR
and enrollment material, receives Pkgi+1 together with the upgrade certificate U and bundle
disclosure, and verifies the package self contained. Genesis adoption persists the release’s next
frontier root only after all predicate checks pass and the receiver’s own canonical commit succeeds. Policy may require online first contact for high value relationships; that is a knob, not
a protocol change. The prepared and proceed disclosure round trip of the previous specification is removed; it existed only to serve receiver witnessed counter reads, which are themselves
removed.
13 Receiver Acceptance Predicate
Definition 11 (Accepted Frontier). For each enrolled holder, the receiver maintains a durable
adopted offline frontier root. A release must chain from it: either the release previous frontier
equals it exactly, or the release carries a verifying Branch Proof (Definition 10) from it to the
11
release previous frontier. If no frontier exists, the relationship is at genesis and genesis adoption
rules apply.
Definition 12 (Offline Acceptance). Acceptoff(Pkgi+1) = 1 iff all of the following hold:
1. all encodings are canonical;
2. the release chains from the receiver’s adopted frontier for the holder (directly or by Branch
Proof );
3. Πi proves Ri commits (B, hi
, ui) through the anchor state leaf;
4. Di+1 recomputes from ∆◦
i+1, and hi+1 = H("DSM/anchor-root-advance/v2" ∥ hi ∥ Di+1);
5. the claimed next anchor counter is ui + 1, using checked arithmetic;
6. rR is the challenge supplied by this receiver, and the recipient field names this receiver;
7. Mi+1 recomputes from the bound fields;
8. ChipVerify(pkchip, Mi+1, σ
chip
i+1 ) = 1 with pkchip pinned in B;
9. HostVerify(pkhost, Mi+1, σhost
i+1 ) = 1 with pkhost pinned in B;
10. the DSM transition proof verifies: ∆◦
i+1 is validly signed under the holder’s DSM device
keys, and Ri → Ri+1 is the correct SMT update including the relationship advance and the
anchor leaf update;
11. Πi+1 proves Ri+1 commits (B, hi+1, ui+1) through the anchor state leaf;
12. the transfer gives the claimed object or value to the receiver, and the authority policy hash
matches;
13. if this is genesis adoption, the upgrade certificate U verifies and binds Ioff to Ion;
14. no known compromise or policy event invalidates the anchor; if verify live policy applies,
the authenticated counter read satisfies H = H0 − (ui + 1) after commit.
The receiver trusts public DSM verification, its own challenge, and the two pinned hardware witnesses. The receiver does not trust host reported state, copied wallet files, or any
unauthenticated field carried inside the release.
14 Power Loss and Recovery
Power may fail between any two operations. The recovery rule is: if a committed release exists,
re emit that same release and finalize that same successor. Recovery never signs a new release
for the same counter step.
12
recover(H0, H, Active):
live = checked_sub(H0, H)
if live == ERROR: return COUNTER_MISMATCH
if firmware_boundary_invalid(): return DOWNGRADE_ONLINE
if Active.status == COMMITTED:
rec = Active.record
if rec.counter_committed == TRUE:
if rec.next_u != live: return DOWNGRADE_ONLINE
return REEMIT_COMMITTED(rec.next_root)
if rec.counter_committed == FALSE:
if rec.next_u == live:
mark_counter_committed(rec)
return REEMIT_COMMITTED(rec.next_root)
if rec.next_u == live + 1:
if rec.prev_root != Active.root: return DOWNGRADE_ONLINE
if rec.bundle != Active.bundle: return DOWNGRADE_ONLINE
counter_update()
mark_counter_committed(rec)
return REEMIT_COMMITTED(rec.next_root)
return DOWNGRADE_ONLINE
if Active.status == PREPARED:
if Active.u != live: return DOWNGRADE_ONLINE
if Active.record.prev_root != Active.root: return DOWNGRADE_ONLINE
if signing_material_present(Active.record):
return ACCEPT_PREPARED_CAN_COMPLETE
return ONLINE_CANCEL_OR_RESOLVE
if Active.status == READY:
if Active.u > live: return FAIL_CLOSED # rolled-back image
if Active.u < live: return DOWNGRADE_ONLINE # missing commits
if H == 0: return EXHAUSTED_ONLINE_ONLY
return ACCEPT(Active.root)
return DOWNGRADE_ONLINE
The Active.u > live branch is impossible for the honest appliance (the counter cannot
rewind) and therefore identifies a restored stale image: fail closed. The Active.u < live
branch identifies host state loss behind the chip: online checked recovery.
15 Online Domain Operation
Online transfers proceed under Ion with DSM signatures alone: no chip, no host key, no counter,
no anchor leaf. Value held by the device is domain agnostic because the device state is one
resource; the relationship, not the value, carries the domain tag. A holder with both domains
13
spends into an offline relationship through the offline protocol and into an online relationship
through ordinary DSM operation, from the same device root lineage.
A holder with only the online domain participates fully in online DSM. This is the zero
hardware entry path: a phone and a seed. The offline domain is added later, if ever, by the
upgrade ceremony, without disturbing any existing relationship.
16 Threat Model
Definition 13 (Software Clone). A software clone holds all host readable state: seed, keys,
chain history, local database, cached proofs, application state. It does not hold the TROPIC01
resident key or counter state, and does not hold the RP2350 partition sealed key.
Definition 14 (Partial Hardware Compromise). A partial hardware compromise yields the non
exportable state of the chip, or of the host partition, but not both, and not the seed.
Definition 15 (Full Stack Compromise). A full stack compromise yields all three factors live:
seed, chip, and host. This includes the malicious owner of an intact appliance.
Definition 16 (Perfect Live State Clone). A perfect live state clone extracts and perfectly
emulates the exact current non exportable state of all three factors. No offline only protocol can
distinguish such an emulation from the original. This is a stated limit, not a defended case.
Behavior of an online domain software clone (same seed, two hosts): both instances hold
Ion. Neither can double spend; whole state consumption admits one successor per parent at
any honest receiver. The two instances diverge at their first independent transfers; the identity
splits; Tripwire exposes the split at first cross contact or reconciliation; counterparties reject both
lineages pending re admission. The clone buys chaos and self bricking, not value. Confidentiality
of the copied state is lost; integrity of the network is not.
PUF fault injection (for example laser assisted) has been demonstrated against PUF constructions in laboratory settings. The design does not rest the offline identity on the PUF alone
for exactly this reason: extracting the chip factor still leaves the attacker without seed and host.
Policy should treat confirmed physical compromise of the chip as grounds for authority rotation.
17 Tripwire Composition
Tripwire supplies fork exposure on reconciliation. Each device commits relationship tips into
its device SMT; a valid receipt proves adjacency from an old root to a new root and binds
the relevant tip update. Tripwire does not make disconnected receivers instantly aware of each
other. It guarantees that conflicting accepted tips cannot survive comparison.
Assumption 1 (Tripwire Security). Assume H is collision resistant and DSM signatures are
secure against chosen message forgery. Then two distinct accepted successors of the same predecessor cannot survive reconciliation without a hash collision, a signature forgery, or a violated
DSM predicate.
In this design Tripwire additionally bricks split identities: once a split is exposed, honest
counterparties refuse both lineages until online re admission under rotated authority.
14
18 Security Claims
Theorem 2 (Birth Non Recreation). Public enrollment data is insufficient to recreate the offline
identity on new hardware.
Proof. B commits Sbirth = H(sbirth), stpub, pkchip, and pkhost. The preimage is destroyed; the
chip keys are non exportable and PUF rooted per die; the host key is partition sealed. A party
with only public data must invert H or extract non exportable state.
Transfer uniqueness is Theorem 1 of Section 9. The claims below are the identity and
durability claims that hardware does carry.
Theorem 3 (Clone Exclusion, Offline Domain). A party lacking any one of the three factors
cannot produce an accepted offline bearer release for an enrolled identity, except by forging a
signature or breaking H.
Proof. Acceptance requires a valid DSM transition under seed derived keys (factor one), σ
chip
under the non exportable chip key pinned in B (factor two), and σ
host under the partition sealed
key pinned in B (factor three), all over the same Mi+1. Absent a factor, the corresponding
signature cannot be produced. In particular a software clone, holding every host readable byte,
produces no offline release at all.
Theorem 4 (Online Domain Scope). Compromise of the phone alone yields the online domain
only.
Proof. The seed suffices for Ion operation by construction. Offline acceptance additionally requires the chip and host signatures by Theorem 3.
Theorem 5 (Stale Image Rejection). An appliance image restored to an earlier state cannot
resume offline bearer operation.
Proof. The restored image commits uold < H0 − H since the physical counter cannot rewind.
Recovery’s Ready branch fails closed on Active.u < H0 − H mismatch in the stale direction, and
any counterparty holding a later frontier rejects the image’s releases on the frontier check; any
authenticated audit read exposes the desynchronization.
Theorem 6 (Identity Split Bricking). Two lineages operating the same identity cannot both
remain accepted in the honest network beyond first exposure.
Proof. The two lineages share a last common state and diverge at some parent. By Theorem 1
no single honest receiver accepts both branches. Receivers on different branches expose the
conflict at first reconciliation or cross contact by Tripwire; thereafter honest counterparties hold
conflicting evidence for one identity and refuse both lineages pending re admission. For the
offline domain, at most one branch satisfies counter synchronization against the live chip, which
additionally identifies the branch carried by the physical appliance.
15
Theorem 7 (Full Stack Adversary Bound). A full stack adversary can construct divergent
offline releases to disconnected receivers with no prior frontier for the holder. Such forks (i)
are never accepted twice by any single honest receiver, (ii) can never merge, (iii) are exposed
and bricked at first reconciliation or cross contact, and (iv) are bounded in count by the offline
exposure cap W between reconciliations.
Proof. (i) is Theorem 1. (ii): distinct successors of the same parent have distinct roots; all
later state commits the divergence. (iii) is Identity Split Bricking. (iv): each committed release
consumes one counter step; policy bounds steps between reconciliations by W, and reconciliation
exposes the split.
Theorem 7 is stated as a detection bound, not a prevention claim, deliberately. Against an
adversary who is the enrolled device, with all three factors live, prevention at a disconnected
first contact receiver is not achievable by any offline only protocol; the previous specification’s
contrary claim rested on counter evidence that did not bind. The honest guarantee is: prevention
against every adversary short of full stack compromise, and bounded, self bricking, always
exposed damage against full stack compromise.
Theorem 8 (Replay Idempotence). Re emitting the same release package does not create a
second spend.
Proof. The package binds the same roots, digest, challenge, and witnesses. A receiver that
accepted it recognizes the identical transition; re emission is duplicate delivery, not a distinct
successor.
Theorem 9 (Recoverable Commit). If the counter moves for a release whose committed candidate is durable, recovery either re emits the same release or downgrades to online recovery; it
never signs a different release for the same counter step.
Proof. By inspection of recover: every branch under COMMITTED returns re emission of the
stored record or downgrade; no branch derives new signing material.
19 TLA+ Sketch
The reduced model captures the software uniqueness invariant and the counter synchronization
invariant. Sessions, pre evidence, and proceed gates of the previous model are gone. NoTwoAcceptedSameOrigin is Theorem 1(i) in mechanical form; CounterSync is Definition 5.
VARIABLES H, Active, Frontier, Delivered
LiveU == H0 - H
Init == /\ H = H0
/\ Active = [status |-> "ready", u |-> 0, root |-> R0, h |-> h0,
record |-> NULL]
/\ Frontier = [r \in Receivers |-> NULL]
/\ Delivered = {}
16
Prepare(pkg) ==
/\ Active.status = "ready"
/\ pkg.prev_root = Active.root /\ pkg.prev_h = Active.h
/\ pkg.u = Active.u /\ pkg.next_u = Active.u + 1
/\ Active’ = [Active EXCEPT !.status = "prepared", !.record = pkg]
/\ UNCHANGED <<H, Frontier, Delivered>>
Commit ==
/\ Active.status = "prepared"
/\ LiveU = Active.u /\ H > 0
/\ H’ = H - 1
/\ Active’ = [Active EXCEPT !.status = "committed"]
/\ UNCHANGED <<Frontier, Delivered>>
Accept(r) ==
/\ Active.status = "committed"
/\ LET pkg == Active.record IN
/\ Frontier[r] \in {NULL, pkg.prev_h}
/\ Delivered’ = Delivered \cup {pkg}
/\ Frontier’ = [Frontier EXCEPT ![r] = pkg.next_h]
/\ Active’ = [status |-> "ready", u |-> pkg.next_u,
root |-> pkg.next_root, h |-> pkg.next_h,
record |-> NULL]
/\ UNCHANGED H
NoTwoAcceptedSameOrigin ==
\A p, q \in Delivered :
(p # q) => ~(p.prev_root = q.prev_root /\ p.prev_h = q.prev_h
/\ p.u = q.u)
CounterSync == (Active.status = "ready") => (Active.u = H0 - H)
20 Wire Protocol
The wire protocol carries the transition core, proofs, and the three factor certificate. The counter
evidence messages and the first transfer disclosure messages of the previous specification are
deleted.
syntax = "proto3";
package dsm.anchor.v2;
message UpgradeCertificate {
bytes anchor_bundle = 1;
bytes online_pubkey = 2;
bytes online_signature = 3; // DsmSign over H("DSM/identity/upgrade/v1"||B)
17
}
message ReleaseCertificate {
bytes anchor_bundle = 1;
bytes sender_device_root_before = 2;
bytes sender_device_root_after = 3;
bytes frontier_root_before = 4;
bytes frontier_root_after = 5;
uint64 anchor_counter = 6;
uint64 next_anchor_counter = 7;
bytes transition_digest = 8;
bytes root_advance_message = 9;
bytes chip_signature = 10; // Ed25519, resident TROPIC01 key
bytes host_signature = 11; // RP2350 partition key
bytes receiver_challenge = 12;
bytes recipient = 13;
}
message BranchHop {
ReleaseCertificate cert = 1;
}
message OfflineRelease {
bytes canonical_transition_core = 1;
bytes smt_proofs = 2;
ReleaseCertificate certificate = 3;
repeated BranchHop branch_proof = 4; // frontier catch-up, optional
UpgradeCertificate upgrade = 5; // genesis adoption only
}
message CounterAudit { // optional verify-live / audit path
bytes anchor_bundle = 1;
uint64 attested_raw_counter = 2;
bytes session_transcript = 3;
}
// Removed relative to dsm.anchor.v1:
// CounterEvidencePre, CounterEvidencePost, CounterAdvanceEvidence,
// AnchorDisclosure-as-gate, BilateralBearerPrepared, BilateralBearerProceed,
// BLE frames 16 and 17.
21 Reference Implementation Requirements
1. accept.rs keeps the anchor state proofs from Ri and Ri+1 and the checked ui + 1 rule.
2. accept.rs replaces all FROM to TO counter verification with the three signature verifi18
cation over Mi+1; the counter appears in acceptance only as the committed pair (ui
, ui+1)
inside signed data.
3. The verifier read API is retained for audit and verify live policy only; it must not gate
default acceptance.
4. Chip provisioning at birth: generate the Ed25519 witness key pair in slot inside TROPIC01
with the non exportable flag; export pkchip and stpub; bind both into B. Clean production
birth uses the default key slot; a used chip whose default slot is unavailable requires an
explicit override, mirroring the slot 1 / slot 2 convention of the counter verifier provisioning.
5. Counter birth: initialize the monotonic counter to H0 at enrollment; lock the initialization
capability where hardware supports it; bind H0 into B.
6. Host provisioning at birth: generate the partition key pair under the seal p0; never export
the private half.
7. MACANDD carries no protocol role. Implementations must not treat MACANDD slot
state as lineage: slot state is a pure function of call input and slot index and is host
restorable, as demonstrated by the vendor reference PIN flow, which re initializes consumed
slots by replaying a derived input. MACANDD may be used for local unlock policy per
the vendor application note; that use is outside this specification.
8. One pending prepared record per frontier; confirm consumes the stored committed release
and never rebuilds a different release for the same prepared step.
9. Production hardware paths must be release builds; if debug assertions are enabled, the
firmware or harness must fail before touching provisioning, prepare, commit, recover, or
audit paths.
10. Firmware measurement gates offline bearer mode. BOOTSEL must not be normally accessible; it must be internal or behind a recessed tamper evident service feature. The USB
connector may remain externally accessible as the power and service interface.
11. Domain separation: relationship establishment records the domain tag; offline domain
establishment requires and verifies the upgrade certificate; online paths must be incapable
of emitting offline releases.
22 Verification Plan
The implementation must include tests for:
1. honest offline transfer with all three signatures succeeds;
2. release missing any one of the three signatures is rejected;
3. chip signature under a key not pinned in B is rejected;
4. host signature under a key not pinned in B is rejected;
19
5. stale frontier release without Branch Proof is rejected; with verifying Branch Proof it is
accepted;
6. second release claiming an already consumed frontier at the same receiver is rejected on
sight;
7. receiver challenge mismatch and recipient mismatch are rejected;
8. post state anchor leaf that does not commit ui + 1 is rejected;
9. restored stale image fails closed in recovery (Active.u behind live counter derived u in
the stale direction);
10. committed recovery re emits the same release and never signs another;
11. online path cannot emit an offline release; offline establishment without upgrade certificate
fails;
12. exposure cap W enforcement at the appliance and its check at reconciliation;
13. replay of an accepted package is recognized as duplicate delivery.
Bench items pending on silicon:
V1. In slot Ed25519 key generation with the non exportable flag on TROPIC01; signing over
a 32 byte M; verification against the exported public key.
V2. End to end three signature release accept on the Pico 2 W appliance against the reference
verifier.
V3. Counter initialization lock behavior after enrollment on a production fresh chip.
23 Silicon Validation of July 8, 2026, Reinterpreted
The July 8, 2026 hardware validation was executed on physical RP2350 plus TROPIC01 appliances running release builds with debug assertions disabled, using the one commit Phase 3
harness and authenticated caged verifier slot reads. Two distinct anchors were exercised:
Run Chip Birth mode Slot H0 Final state
A used chip A bench adopted 2 4294967281 u=1, H=4294967280
B clean chip production fresh 1 4294967294 u=1, H=4294967293
Clean chip anchor identifier: 8RPYNMX7G26GNTQB3BKFK4QXEKJEW0CVTSARZ8BVB2T9ZADGQ3V0.
Used chip A anchor identifier: 1SZ0KC8H6WJ0JYMX2YDD49VM8RX4R6ZGKCK692FDBDZ186HYN15G.
Under the claims of this specification, the run validates:
1. counter birth: a virgin chip’s uninitialized counter was initialized to the maximum, read
back, and adopted as H0;
20
2. prepare moves nothing: witness and certificate formation left the counter untouched;
3. commit discipline: exactly one counter update per commit; H decremented by exactly
one;
4. second commit refusal: the appliance refused a second commit against the same prepared
transition, and H remained stable after the refusal;
5. synchronization: u = H0 − H held at every observation point on both chips;
6. per die identity: the two chips presented distinct static public identities (d1 87 bc f1
... and d1 b5 79 bf ...), the empirical basis of the PUF rooted per die uniqueness
that the offline identity fuses.
What the run does not validate under the new claims: the receiver witnessed FROM and TO
evidence path it was originally built to demonstrate. That path is removed from the protocol;
the reads survive as the optional audit facility of Section 11. The in slot Ed25519 witness
path (V1, V2) is the remaining bench work before the reference implementation matches this
document.
24 Changes from the Previous Specification
Identified during adversarial review, July 2026.
1. The counter is demoted from authority to floor. A scalar counter read proves the
chip’s coordinate, freshly, over a session. It never proves the chip reached that coordinate
because of this transition: the counter primitive does not see Mi+1, and binding metadata
wrapped around a scalar is receiver asserted, not chip attested. Two receivers could
witness the same physical decrement as their own. The apparatus built on those reads,
CounterEvidencePre, CounterEvidencePost, CounterAdvanceEvidence, and predicate checks
18 through 23 of the previous acceptance definition, is removed.
2. Transfer uniqueness moves to software, where it already lived. The device state
consumes itself as a whole; one parent, one accepted successor. Theorem 38 (Counter Step
Uniqueness) and the counter argument of Theorem 43 of the previous specification are
replaced by Theorem 1, which uses no hardware and is proved from the SMT structure
itself through Lemmas 1, 2, and 3.
3. The SMT committed counter becomes the authoritative position register. The
previous specification committed ui
in the anchor state leaf but treated the physical counter
as the authority and the leaf as corroboration. This specification inverts the relation: the
SMT counter is the authoritative software position, consumed with the whole state, and
the physical counter is a tracker bound to it one to one.
4. MACANDD is removed from the acceptance path. MACANDD slot state is a
pure function of call input and slot index and is host restorable; it carries no forward
only lineage. The MACANDD derived one time witness key is replaced by a resident non
exportable Ed25519 key, portable and offline verifiable.
21
5. The fused anchor head and boot ticket chain are removed as cryptographic
objects. Their job, refusing resumed copied images and new hardware, is done by the
three factor identity (a copied image lacks chip and host) and by the counter floor (a stale
image fails closed). Firmware measurement survives as an implementation gate.
6. The first transfer disclosure round trip is removed. BilateralBearerPrepared and
BilateralBearerProceed existed only to obtain a live FROM read before commit. With the
reads removed, first transfer offline is one round trip like any transfer, plus the upgrade
certificate at genesis.
7. The dual domain structure is added. Online identity from BIP39 alone, zero hardware; offline identity as a three factor fusion; permanent coexistence; upgrade ceremony.
This removes the hardware cost barrier from online participation entirely.
8. The full stack adversary claim is corrected. The previous specification claimed on
sight double spend exclusion against a breached partition. Against full stack compromise,
no offline only protocol prevents divergent releases to disconnected first contact receivers;
the previous claim rested on evidence that did not bind. The corrected claim, Theorem 7,
is prevention against everything short of full stack compromise and bounded, exposed, self
bricking damage against it.
25 Limits
1. Perfect live emulation of all three factors is outside offline distinguishability.
2. Full stack compromise, including the malicious owner, yields detection grade rather than
prevention grade security at disconnected first contact receivers, bounded by the exposure
cap and bricked on exposure (Theorem 7).
3. PUF constructions have been attacked by fault injection in laboratory settings; the design
tolerates chip factor extraction by fusion, and policy should rotate authority on confirmed
physical compromise.
4. The online domain is single factor by design; phone compromise is online domain takeover.
Users holding significant value should hold it in offline domain relationships.
5. Counter exhaustion at H = 0 forces online only operation until authority rotation; lifetime
capacity is bounded by H0, the exposure cap, and flash wear.
6. Theft of the complete appliance with the phone and seed is full stack compromise; local
unlock policy (outside this specification) is the mitigation.
7. Tripwire exposes forks at reconciliation, not instantly across disconnected receivers.
26 Security Position
For programmable security between mutually distrustful parties, this design differs from a
blockchain and from prior secure element cash. A blockchain prevents double spend by global
22
ordering under consensus assumptions. Prior secure element designs prevented it by making
the hardware the transaction authority, and inherited the hardware’s full attack surface as the
protocol’s attack surface. This design does neither:
transfer uniqueness is a software property of whole state consumption;
hardware proves only that the device is the device.
The claim is narrow and strong: no honest receiver accepts two successors of one origin
(Theorem 1, hardware free per Corollary 1); no party short of full three factor compromise
produces any offline successor at all; and a full stack adversary buys only bounded, exposed,
self bricking divergence. The hardware trust surface has been reduced to two non exportable
keys and one monotonic counter, and the protocol’s correctness argument does not reference the
hardware at all.
27 Conclusion
The previous specification asked hardware to do what software already did, and the machinery
required to make the hardware appear to do it, receiver witnessed counter reads, MACANDD
derived witnesses, fused heads, boot tickets, disclosure round trips, was the bulk of the document.
Removing the misassignment removes the machinery.
What remains is small. DSM consumes state whole; one parent, one successor; that is
transfer uniqueness, and it is software. Identity is two domains: a seed for the online world, at
zero hardware cost, and a three factor fusion of seed, PUF rooted chip key, and partition sealed
host key for the offline world, in which every release is witnessed by all three. The counter is a
floor, a tripwire, and a budget. Tripwire bricks whatever splits.
The July 8, 2026 silicon run stands as validation of the counter discipline and the per die
identity on which the offline domain rests. The remaining bench work is the resident witness
key path. The offline bearer design is no longer a hardware authority with a software veneer. It
is a software authority with a hardware identity, which is what a Deterministic State Machine
required all along.
References
[1] J. O’Connor, J.-P. Aumasson, S. Neves, Z. Wilcox-O’Hearn. BLAKE3: One Function, Fast
Everywhere.
[2] L. Lamport. Specifying Systems: The TLA+ Language and Tools for Hardware and Software
Engineers.
[3] R. Merkle. A Certified Digital Signature. Advances in Cryptology, CRYPTO 1989.
[4] D. J. Bernstein, N. Duif, T. Lange, P. Schwabe, B.-Y. Yang. High-speed high-security signatures.
[5] M. Palatinus, P. Rusnak, A. Voisine, S. Bowe. BIP-0039: Mnemonic code for generating
deterministic keys.
23
[6] Tropic Square. TROPIC01 Datasheet and Application Note ODN TR01 app 002 (PIN Verification).
24