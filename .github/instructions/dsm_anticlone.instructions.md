---
applyTo: '**'
---
An Attested Device Identity for Oﬄine Anti Cloning
in Deterministic State Machines
From physical continuity to a hardware root of trust, with empirical validation on an
open secure element
Cryptskii
Irrefutable Labs Inc.
June 2026
Abstract
A deterministic state machine that clears value bilaterally and oﬄine faces a sharp ques-
tion: can a participant who holds a perfect bit copy of another participant’s device, including
the full state chain, every private key, and the wallet seed, continue that participant’s lin-
eage and spend the same value twice. This document develops the answer in two stages.
First it proves a ceiling: on any device with no hardware island the owner cannot rewrite,
every software readable physical signal that one might use as an anti clone anchor is either
forgeable by a root level adversary or unobtainable by the honest application, so no software
only physical channel can bind a transition against a copy on other hardware. The argu-
ment is supported by direct measurement, a battery channel that is real but lives behind
a gauge the kernel owns, and a current Android platform that locks the memory channel
away from unprivileged code. Second it states and instantiates the necessary and suﬃcient
condition: exactly one hardware island the owner cannot rewrite, a secure element holding
a non extractable key under verified boot, suﬃces to bind each transition with a signature
that a copy on other silicon cannot produce. The construction is then validated end to
end against a physical Trezor Safe 7, an open dual secure element device, reachable from a
third party host on stock firmware. We report the verified device authentication, the exact
signed message construction, the two stable per device identities, and the chain to a genuine
production root, together with an honest accounting of what was not yet demonstrated and
where the mechanism is strong rather than absolute.
1 Introduction
DSM is a deterministic state machine for bilateral, oﬄine value transfer. Two parties advance
shared state by exchanging signed transitions; there is no global consensus and no online set-
tlement in the common path. This design buys strong properties, low latency, no network
dependence at the moment of transfer, no third party in the loop. It also creates a specific
adversary that a chain with online settlement does not have to face directly: the oﬄine clone.
The oﬄine clone is not a replay of old messages and not a stolen key used online. It is a
participant who takes a complete copy of a counterparty’s device state and attempts to operate
as that counterparty from a second machine, advancing the lineage in a way that forks value.
The defense cannot rely on a network check, because the feature in question is precisely the
oﬄine one. So the question becomes physical and local: is there something a genuine device can
present with each transition that a perfect copy on diﬀerent hardware cannot present, checkable
by an oﬄine verifier, with no online gatekeeper.
This document answers that question. Section 2 fixes the threat model. Section 3 proves
that software only physical channels cannot do the job and shows the supporting measurements.
Section 4 states the necessary and suﬃcient condition. Section 5 gives the construction and the
1
reason to bind a device identity rather than a wallet seed. Section 6 places the choice against
the properties web3 cares about. Section 7 instantiates the construction on a Trezor Safe 7 and
Section 8 reports the live validation. Section 9 is an honest accounting of limits. Section 10
describes how this fits DSM without becoming a hard dependency for the rest of the protocol.
2 Threat model
We grant the adversary as much as is realistic for a device that left the owner’s control.
Definition 1 (Perfect bit copy). The adversary obtains a complete copy of a participant’s
persisted state: the full state chain, all private keys, and the wallet seed or its backup. The
adversary may load this copy onto hardware of their choosing and may hold root on that
hardware, that is, may replace the kernel, drivers, and firmware on the machine that runs the
copy.
The adversary trivially can read and replay old state, because a copy contains it. That is
not the threat. The threat is forward motion.
Definition 2 (Clone continuation). A clone continuation is the production of new state tran-
sitions, by the copy, that an honest oﬄine verifier would accept as a canonical extension of the
original lineage. A scheme defeats cloning if it makes clone continuation infeasible while leaving
genuine continuation cheap.
Two points fix the scope. First, cryptographic authenticity of a transition, a valid signature
over well formed content, does not by itself prevent clone continuation, because the copy holds
the signing keys and can produce valid signatures over chosen content. A chain proves authorship
and ordering, not that the author is the unique physical device. Second, the determinism of
the state machine is a property of the transition function, not of input truth; a deterministic
function fed a fabricated but well formed input produces a valid looking output. The anti clone
property must therefore come from an input the copy cannot fabricate, not from the correctness
of the function.
3 The failure of software only physical anchors
A natural idea is to anchor each transition to a live physical signal that the genuine hardware
emits and a copy on other hardware would not reproduce: battery internal resistance, fuel gauge
voltage under load, memory timing, thermal response, clock skew. We show this cannot work
on the devices DSM must run on.
Definition 3 (Physical channel). A physical channel is any value derived from device hardware
that software can read and that one might hope is device specific.
Definition 4 (No attestation device). A no attestation device is one with no hardware island
the owner cannot rewrite. Every read path that delivers a physical value to software passes
through code, kernel, drivers, firmware, that the device owner can replace.
Lemma 1 (The one handoﬀ). On a no attestation device, for every physical channel C at least
one of the following holds:
(a) C is forgeable by root. The owner controls the read path for C and can substitute a chosen,
self consistent value at the point where C is handed to software.
(b) C is unmeasurable without root. Reading C at the fidelity needed to fingerprint the device
requires privileges the application does not hold on a stock, unrooted system.
2
Argument. Every physical channel becomes useful only at the moment a physical quantity is
turned into a number that software consumes. Call this the handoﬀ. On a no attestation device
the code that performs the handoﬀ is owned by the device owner. If an application can reach
the handoﬀ with ordinary privileges, then so can a root adversary on the cloning machine, and
the adversary, owning the code at the handoﬀ, can emit any value it likes, internally consistent
with whatever cross checks the scheme applies, which is case (a). If an application cannot reach
the handoﬀ with ordinary privileges, then the honest application cannot use C on the devices it
must run on, and obtaining C requires exactly the elevated privilege that, on the adversary side,
enables case (a). There is no third option, because there is no point of access to a physical value
other than through the handoﬀ, and the handoﬀ is owned by whoever owns the machine.
Remark 1. The Lemma is independent of the channel. Switching from battery to memory to
a software emulated physical function to a so called live reading never escapes it, because each
alternative still has a single handoﬀ on hardware the owner controls. Live does not mean true.
A value can be sampled at the instant of use and still be a value chosen by the kernel that did
the sampling.
3.1 Measurement: the battery channel is real but owned
We examined the battery channel on two same model handsets, Samsung Galaxy A16, model
SM-A165M, MediaTek Helio G99, Android 16, kernel 6.12. Internal resistance does diﬀer be-
tween two same model cells: one unit measured roughly 52 to 56 milliohms, the other roughly
67 milliohms, about a 20 percent spread. That is a genuine per cell property. Two things
defeat it as an anchor. The thermal response curves of the two same model units overlap, so
a thermal signature does not separate same model devices. More fundamentally, every such
reading reaches software through a fuel gauge whose driver the device owner’s kernel controls,
which is case (a) of Lemma 1: a root clone reports whatever internal resistance and gauge curve
it wishes, self consistently.
3.2 Measurement: the memory channel is locked away
We then asked whether an unprivileged application could fingerprint the device through memory,
the route a Rowhammer style or timing based scheme would take. On the same Android 16
devices the application facing surface is closed. There is no /dev/ion. The /dev/dma_heap
interface exists but is system owned and not openable by an application. Physical frame numbers
in /proc/self/pagemap are gated for unprivileged readers. /proc/iomem returns permission
denied. App level physical memory addressing, the prerequisite for memory fingerprinting, is
therefore infeasible without root or a custom kernel, which is case (b) of Lemma 1. The honest
application cannot obtain the channel on a stock device, and the only way to obtain it is the
same elevation that lets the attacker forge on the other side.
3.3 The ceiling
Theorem 1 (Necessity of hardware). Let a binding scheme attach to each transition a token that
an oﬄine verifier can check and that a perfect bit copy on diﬀerent hardware cannot reproduce.
On a no attestation device, no such scheme exists for software derived physical channels.
Argument. The token must depend on something the copy lacks. The copy holds every bit, so
the missing ingredient must be a live physical value the original hardware produces and the
copy’s hardware does not reproduce identically. By Lemma 1 that value is either forgeable by
the attacker’s root, in which case the copy reproduces it and the token does not distinguish, or
unobtainable by the honest original’s application, in which case the scheme cannot run where
it must. Either way the scheme fails to bind.
3
4 The necessary and suﬃcient condition
Theorem 1 closes the software only door and points at exactly what is missing: a place where
the owner does not own the handoﬀ.
Definition 5 (Hardware root of trust). A hardware root of trust is a hardware island holding
a private key that is generated on the island and never leaves it, so there is no read path to
the key, and that will sign only under a measured, verified condition. A secure element under
verified boot is an instance.
Theorem 2 (Suﬃciency). A hardware root of trust suﬃces to construct the binding. Attach to
each transition a signature, by the island’s non extractable key, over the transition’s own content
used as a fresh challenge, and have the verifier check that signature against the island’s attested
public identity. A perfect bit copy on diﬀerent silicon holds every bit but not the island’s key,
because the key has no read path, and therefore cannot produce the signature, so its transitions
are rejected. The genuine device produces the signature on demand from its own island, so
genuine continuation stays cheap.
Corollary 1. The secure element delivers, as one primitive, the property the battery and mem-
ory attempts were reaching for: a per transition value that is cheap for the genuine device to
produce and infeasible for a copy on other hardware to reproduce. The diﬀerence is decisive.
The physical channel values are either forgeable or unobtainable. The secure element value is
uncopyable by construction, no read path, attested origin.
Remark 2. The condition is minimal. It asks for exactly one island the owner cannot rewrite,
not for a locked down phone, not for a remote verdict. Everything else in DSM continues to
run on ordinary, fully owned hardware.
5 Construction: bind the device identity, not the seed
The anchor must be an identity that cannot be backed up. This rules out the obvious candidate.
A wallet seed is recoverable by design. The owner can restore it from a backup onto a fresh
device, which is the property users want for funds and exactly the property that makes a seed
copyable. A seed is therefore useless as an anti clone anchor: the adversary restores it and is
indistinguishable on that axis.
A device attestation identity is the opposite. It is generated on the secure element, has no
backup, has no read path, and is not recoverable. DSM binds lineage to this attestation identity
and treats the seed as orthogonal wallet material. Funds remain recoverable through the seed;
lineage continuity is gated by the unrecoverable device identity.
Concretely, let hn be the canonical hash of transition n. The device computes
sn = Signisland(frame(hn)),
where frame is the device authentication framing of Section 8. The next canonical hash folds
the signature and the island identity:
hn+1 = H(hn, payloadn+1, sn, idisland).
An oﬄine verifier, given the lineage and the pinned idisland, checks each sn against frame(hn)
and idisland. A copy on other silicon cannot produce sn, so it cannot extend the lineage. A copy
with no secure element cannot sign at all. Replay is handled because the signed challenge is
the transition’s own hash, which is fresh per transition.
4
6 Positioning: the oﬄine anti cloning trilemma
Three properties are each desirable for an oﬄine anti clone gate.
(i) No outside gatekeeper. No remote party need be online to approve a transfer, and no
vendor can censor or exclude a class of devices or operating systems.
(ii) Runs on existing phones. No special hardware beyond what people already carry.
(iii) Beats root oﬄine. A copy on attacker controlled hardware is rejected with no network
check.
No mechanism delivers all three.
A purely software physical channel oﬀers (i) and (ii) but not (iii), by Theorem 1. A remote
vendor attestation, for example a platform integrity verdict, oﬀers (ii) and (iii) but not (i): it
phones home, it can exclude alternative operating systems and rooted but honest devices, and
it installs the vendor as a gatekeeper, which is the precise property web3 was built to remove.
A local hardware root of trust, an open secure element the user holds, oﬀers (i) and (iii) and
relaxes (ii) by asking the user to hold one small extra device.
DSM takes the third corner. It keeps the open, local, oﬄine property and accepts that the
oﬄine bearer feature wants a held secure element. The element is the user’s own root of trust,
not a remote verdict, so it does not reintroduce the gatekeeper. This is the distinction that
matters for the audience: a local and open root of trust is the acceptable form, a remote and
vendor gated verdict is the rejected form, and the two are not interchangeable even though both
are called attestation.
7 Instantiation on the Trezor Safe 7
We instantiate the construction on a Trezor Safe 7, internal designation T3W1. It is a useful
target for three reasons. It carries two secure elements whose attestation is open and auditable
rather than a closed vendor verdict. Its device authentication is reachable from a third party
host, not only the vendor’s own application. And it runs the construction on stock firmware,
so nothing about the demonstration depends on a modified build.
The two elements are an Infineon OPTIGA Trust M, signing ECDSA over NIST P256, and
a TROPIC01, signing Ed25519. The TROPIC01 is the more open of the two and is the element
we propose DSM bind to. The device exposes an AuthenticateDevice operation over its host
protocol: the host sends a challenge, and the device returns, per element, a leaf certificate chain
and a signature over the framed challenge. The leaf certificate carries a per device key whose
hash is a stable device identity, and the chain links that leaf to the vendor’s manufacturing
certificate authority and on to a production root.
8 Empirical validation
We drove a physical Safe 7 from an ordinary host over the device’s host protocol, on stock
firmware, and verified the result oﬄine against the vendor’s published verifier and production
roots. Funds and seed were never touched.
8.1 The signed message construction
The device does not sign the raw challenge. It signs a framed message: one length byte, then
the ASCII string AuthenticateDevice:, then one length byte, then the challenge. For a 32
5
byte challenge this is the prefix byte 0x13, the 19 character label, the prefix byte 0x20, then
the 32 bytes:
frame(c) = 0x13 ∥ "AuthenticateDevice:" ∥ 0x20 ∥ c.
The OPTIGA element signs ECDSA over P256 with SHA256 of this message; the TROPIC01
element signs Ed25519 over this message. Pinning this exact framing was necessary: a verifier
that omits the challenge length byte rejects a genuine signature.
8.2 Result
Both elements verified cleanly. For each, the signature over our fresh challenge verified, the
leaf certificate was issued by the Trezor Manufacturing CA, that CA was issued by the Trezor
Manufacturing Root CA, and the chain resolved to a genuine Trezor Safe 7 production root
that ships in the vendor library, with the development flag false. Both elements resolved to the
same root authority. Table 1 summarizes the device and the two identities.
Field Value
Model Trezor Safe 7 (T3W1)
Serial 47312152500AMf
OPTIGA element ECDSA P256, 71 byte DER signature
TROPIC01 element Ed25519, 64 byte signature
Challenge bound yes, under the framing above
Chain leaf to Manufacturing CA to Root CA to production root
Development root no
Both legs same root yes
Table 1: Verified device authentication on a physical Safe 7.
The two per device identities, taken as the SHA256 of each leaf subject public key info, are
the values DSM would bind to:
OPTIGA leaf SPKI sha256: 80
f077a1d5e6061dde9762e35f5fd42ea79e27cbb7996970d2e6d4f68cf5af37
TROPIC01 leaf SPKI sha256:
c3dd6f39841476e326f690518339c7fb88e4ca99ba08ad89bf05b83f4ca33f3b
8.3 Stability
We ran the operation twice, with two diﬀerent random challenges. The two per device identity
hashes were byte identical across both runs while the challenges diﬀered. The identity is fixed
in the silicon and does not move from run to run, which is the property a binding requires: the
anchor is stable, only the signed challenge changes.
8.4 What this establishes
Four things that were open are now closed by direct measurement. The device authentication is
reachable from the owner’s own host on stock firmware, not only from the vendor application.
The signature binds our specific fresh challenge under the correct framing, which is replay
resistance demonstrated rather than assumed. The certificate chain reaches the genuine vendor
production root, so the identity is the real one and not a self signed fake. And the device
presents two stable identities that are constant across runs. The remaining positive claim, that
a second genuine unit yields a diﬀerent identity that the binding would reject, is the one item
not yet measured, discussed in Section 9.
6
9 Security analysis and honest limits
The mechanism is strong. It is not magic, and the following are stated plainly so the design is
built on what is real.
1. The clone rejection case is not yet empirically shown. Only one Safe 7 was available.
We proved a stable identity and a genuine root on that unit. We did not yet observe a second
genuine unit producing a diﬀerent identity that the binding rejects. The construction implies
it, since each element’s key is unique and non extractable, but the negative case remains
to be demonstrated and should be, with a second unit, before the claim is presented as
measured rather than argued.
2. This attestation is classical, not post quantum. The device authentication we verified
uses ECDSA over P256 and Ed25519, both classical. The vendor’s post quantum claim
concerns the boot, firmware update, and device firmware signing path, which uses a post
quantum scheme, not these attestation keys. The anti clone binding should therefore not
be described as post quantum on the strength of this evidence. If post quantum binding is
required, it needs a separate post quantum attestation surface or an additional post quantum
signature folded in.
3. Pin the specific device identity. Our oﬄine verification trusted any genuine vendor
production root, because it ran with an empty allow list. For DSM, pin the specific device
identity, or at minimum the specific production root, so that a diﬀerent genuine device of
the same make cannot stand in for the bound one. This is a one line allow list, not a gap in
the result, but it must be set before deployment.
4. Attestation is strong, not absolute. A determined adversary with physical possession
and laboratory capability can attack secure element attestation. Published work against
an earlier model’s authenticity and firmware checks shows the bar is high but finite. The
mechanism raises the cost of a successful clone by orders of magnitude and shifts the attack
from a software copy anyone can make to a hardware attack few can mount; it does not
make cloning provably impossible.
5. Custom firmware is in tension with stock attestation. Unlocking the bootloader to
ship custom DSM firmware would trip the attestation and firmware checks that make the
stock device trustworthy. The near term path keeps stock firmware and uses the device
authentication as an external oracle. A custom firmware path is possible but would carry
its own signing keys and a diﬀerent trust story, and should not be conflated with the stock
result reported here.
6. Operational friction is real but not a security property. The current host transport
re pairs each session and shows a short code on the device. This is usability, not security,
and can be removed by persisting the pairing credential. It is noted so that a reviewer does
not mistake the friction for a limitation of the binding.
10 Integration with DSM and scoping
The most important design decision is to keep this optional and narrow.
DSM core, the bilateral state machine, the continuity logic, the Tripwire detection, and
recovery, requires no attestation and runs everywhere, including on rooted devices and devices
with no secure element. Attestation gates only the optional oﬄine bearer transfer feature, the
case where a device asserts, with no network, that it has not been cloned. If a device cannot
attest, no secure element present, or attestation fails, DSM falls back to online checked transfers.
7
The user loses the oﬄine convenience for that transfer and loses nothing else: not safety, not
the rest of the protocol, not access to funds. The hard dependency is therefore confined to a
single optional feature, and the large majority of DSM is untouched by any of this.
This scoping also answers the deployment objection. A mechanism that required every user
to hold a secure element for any use of DSM would be a non starter. A mechanism that requires
it only for oﬄine bearer transfers, and degrades gracefully to an online checked path otherwise,
is something a user opts into for a specific convenience, with a clear and bounded cost.
11 Conclusion
The path from a battery continuity idea to a working anchor was not a series of better physical
signals. It was the recognition that no software readable physical signal can bind a transition
on hardware the owner controls, because the lie always has one place to live, the single handoﬀ
where a physical value becomes a number in software. The fix is not a cleverer signal but a
diﬀerent kind of place: one hardware island the owner cannot rewrite, holding a key with no
read path, that signs only what it is asked under a verified condition. That is necessary, by the
ceiling theorem, and suﬃcient, by the construction.
The contribution here is that the suﬃcient condition was not left as theory. It was run against
a physical, open, dual secure element device on stock firmware, from an ordinary host, and
verified to a genuine production root, with two stable identities and a challenge bound signature
under the exact published framing. The uncopyable per transition value that the physical
channels were chasing exists, today, on a small device a user can already hold. Binding DSM’s
oﬄine bearer lineage to that device identity is a concrete, measured, and appropriately scoped
way to defeat the oﬄine clone, with the limits above stated honestly so that the engineering
rests on what was actually shown.
A Signed message construction and verification
The verifier reconstructs the framed challenge and checks the leaf signature, then walks the
certificate chain to a pinned root.
frame(challenge):
0x13 || "AuthenticateDevice:" || 0x20 || challenge
where 0x13 = 19 = len("AuthenticateDevice:")
0x20 = 32 = len(challenge)
verify(challenge, signature, cert_chain, pinned_root, pinned_identity):
msg = frame(challenge)
leaf = parse(cert_chain[0])
require leaf.verify(signature, msg) # challenge binding
require sha256(leaf.spki) == pinned_identity # device identity pin
for issuer in cert_chain[1:]:
require child issued_by issuer # chain walk
child = issuer
require top issued_by pinned_root # genuine root
B Captured evidence
From the pinning run on the physical Safe 7. The challenge was randomly generated by the
host; the signatures are the device’s response over the framed challenge.
challenge:
8
52a36b23b8323283126036d31b0c8aae49dbee9eeddfbfaf10c02b8c7b2ad52f
OPTIGA signature (ECDSA P256, DER):
3045022009b598676a4bd44b1ec630504c9c9c97a1aa24c60fa9ea70f1fcd7f2c9c5
02c4022100cb0f668348ec2c16a39184292a222d0c639a4cdfcfbceb713b51431869
cf8a37
TROPIC01 signature (Ed25519):
65b26d38c43c0d4b3ea3dcc8427c9b1d7e781381d370f8ca1dfebc7eb614d8c6d25c
ac379cd7fd159bbabd1880459d9330566f458a6cf5ae418b345a4b053e01
OPTIGA leaf SPKI sha256:
80f077a1d5e6061dde9762e35f5fd42ea79e27cbb7996970d2e6d4f68cf5af37
TROPIC01 leaf SPKI sha256:
c3dd6f39841476e326f690518339c7fb88e4ca99ba08ad89bf05b83f4ca33f3b
9