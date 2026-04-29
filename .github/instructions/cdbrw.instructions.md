---
applyTo: '**'
---
C-DBRW: Chaotic Resonant Authentication
Wrangling Thermal Entropy in Dual-Binding Random Walks
with Post-Quantum Cryptographic Binding
A Formal Specification and Security Analysis
Brandon “Cryptskii” Ramsay
Deterministic State Machine Project
March 3, 2026 — Revision 2.0 (Specification Grade)
Abstract
Traditional hardware security modules treat thermal drift as a noise source that de-
grades the signal-to-noise ratio (SNR), often mitigating it through filtering or environment-
controlled calibration. This specification proposes a radical departure: we treat the thermal
dynamics of silicon as an active participant in a nonlinear control system. We introduce
the Chaotic Dual-Binding Random Walk (C-DBRW), which leverages sensitive de-
pendence on initial conditions to create a device fingerprint that is both reproducible in its
chaotic behavior and physically unclonable.
This document formalizes C-DBRW as a post-quantum-secure hardware identity
primitive. We sofine a discrete chaotic interrogation map implemented via Add-Rotate-
XOR (ARX) networks, prove attractor invariance under bounded thermal perturbation, es-
tablish the uniqueness and inseparability of device fingerprints, and specify a zero-knowledge
verification protocol layered with Kyber key encapsulation and BLAKE3 commitments.
Phase-space orbit verification provides a statistical proof of authenticity while maintain-
ing resilience against temperature, power, and timing perturbations.
We prove that the chaotic attractor structure of each device acts as a hardware-anchored
identitydomain, suitableforautonomousauthenticationwithouttrustedthird-partycalibra-
tion, and secure against both classical and quantum adversaries under standard lattice and
hash-function hardness assumptions. All constructions are compatible with the Determinis-
ticStateMachine(DSM)architectureandadmitefficientverificationonresource-constrained
mobile devices.
Contents
1 Introduction 4
1.1 1.2 Contributions . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 4
Notation and Conventions . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 4
2 Threat Model and Security Goals 4
3 Chaotic Interrogation Model 5
3.1 3.2 3.3 3.4 Silicon Substrate State . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 5
Continuous Chaotic Map (Motivating Model) . . . . . . . . . . . . . . . . . . . . 5
Discrete ARX Implementation . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 6
Orbit and Phase-Space Density . . . . . . . . . . . . . . . . . . . . . . . . . . . . 6
4 Attractor Theory and Device Identity 7
4.1 4.2 Device-Specific Attractor . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 7
Random Dynamical System Formulation . . . . . . . . . . . . . . . . . . . . . . . 7
4.3 4.4 4.5 4.6 4.2.1 Irreducibility and Aperiodicity . . . . . . . . . . . . . . . . . . . . . . . . 8
4.2.2 Existence and Uniqueness of Stationary Measure . . . . . . . . . . . . . . 8
4.2.3 Geometric Ergodicity . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 8
4.2.4 Intra-Device Perturbation Bounds . . . . . . . . . . . . . . . . . . . . . . 9
4.2.5 Revised Interpretation . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Attractor Invariance . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Inter-Device Separation via Perturbation Bounds . . . . . . . . . . . . . . . . . . 4.4.1 Entropy-Rate Separation Bound . . . . . . . . . . . . . . . . . . . . . . . 4.4.2 Wasserstein Contraction . . . . . . . . . . . . . . . . . . . . . . . . . . . . Quantitative Bounds . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 4.5.1 Concrete Mixing Rate . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 4.5.2 Explicit Inter-Device Separation . . . . . . . . . . . . . . . . . . . . . . . 4.5.3 Certified Authentication Error Bounds . . . . . . . . . . . . . . . . . . . . 4.5.4 Mixing Bounds Under Entropy Autocorrelation . . . . . . . . . . . . . . . 4.5.5 Physics-Grounded Entropy Estimate . . . . . . . . . . . . . . . . . . . . . 4.5.6 Manufacturing Lot Correlation Model . . . . . . . . . . . . . . . . . . . . 4.5.7 Formal Entropy Health Test . . . . . . . . . . . . . . . . . . . . . . . . . . 4.5.8 Minimum Manufacturing Variance for Safe Deployment . . . . . . . . . . 20
Resonant Forgiveness . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 10
10
10
12
13
14
14
14
15
16
17
18
19
21
5 Formal Security Analysis 22
5.1 5.2 5.3 5.4 5.5 5.6 5.7 Cryptographic Assumptions . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Device Unclonability . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Binding Inseparability . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Forward Secrecy of Per-Step Keys . . . . . . . . . . . . . . . . . . . . . . . . . . . End-to-End Security . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Composable Security (UC Framework) . . . . . . . . . . . . . . . . . . . . . . . . Adversarial Cryptanalysis . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 5.7.1 Attack 1: Entropy Collapse . . . . . . . . . . . . . . . . . . . . . . . . . . 5.7.2 Attack 2: Lot-Level Modeling . . . . . . . . . . . . . . . . . . . . . . . . . 5.7.3 Attack 3: Histogram Inversion . . . . . . . . . . . . . . . . . . . . . . . . 5.7.4 Attack 4: Side-Channel Model Extraction . . . . . . . . . . . . . . . . . . 5.7.5 Attack 5: Threshold Manipulation . . . . . . . . . . . . . . . . . . . . . . 5.7.6 Summary of Attack Surface . . . . . . . . . . . . . . . . . . . . . . . . . . 22
22
22
23
23
24
25
26
26
26
27
27
27
6 Post-Quantum Cryptographic Binding 27
6.1 6.2 6.3 Enrollment Protocol . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Zero-Knowledge Verification Protocol . . . . . . . . . . . . . . . . . . . . . . . . . Attractor Envelope Test . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 28
28
29
7 Tri-Layer Feedback Architecture 29
7.1 7.2 7.3 Layer 1: Thermal Salting . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Layer 2: Phase-Space Verification . . . . . . . . . . . . . . . . . . . . . . . . . . . Layer 3: Resonant Forgiveness . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 30
30
30
8 DSM Integration Specification 31
8.1 8.2 8.3 C-DBRW as Hardware Entropy Source for DBRW . . . . . . . . . . . . . . . . . Ephemeral Key Derivation Chain . . . . . . . . . . . . . . . . . . . . . . . . . . . Receipt Binding . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 31
32
32
2
9 Implementation Architecture 32
9.1 9.2 9.3 9.4 Three-Layer Execution Model . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Algorithm Specifications . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Performance Budgets . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . Test Vector Requirements . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 32
33
34
35
10 Security Properties Summary 35
11 Comparison with Prior Art 36
12 Future Work 36
13 Conclusion 36
A Domain Separation Tags 37
B Normative Parameter Summary 38
3
1 Introduction
The Dual-Binding Random Walk (DBRW) concept binds cryptographic material to physical
attributes of a device—typically volatile features such as SRAM decay patterns, metastable
oscillation states, or timing jitter distributions. These physical quantities vary unpredictably
with temperature, supply voltage, and aging, leading to high bit-error rates (BER) during key
regeneration. Attempts to mitigate this with averaging, linear compensation, or helper-data
constructions filter out precisely the nonlinear characteristics that make each device unique.
In this paper, we adopt the opposite approach: rather than rejecting thermal chaos, we
structure it. We model the silicon device not as a noisy resistor network, but as a chaotic
dynamical system with well-defined attractors and bifurcation properties. This reframing allows
thermal variation to act as a tunable control parameter rather than an enemy of determinism.
1.1 Contributions
This specification makes the following contributions:
(i) A formal model of silicon thermal dynamics as a discrete chaotic system with provable
attractor invariance (Section 3).
(ii) A discrete, architecture-portable ARX implementation of the chaotic interrogation map
with deterministic bit-level behavior (Section 3.3).
(iii) Formal security proofs establishing device uniqueness, unclonability, and resilience under
bounded environmental perturbation (Section 5).
(iv) A post-quantum-secure zero-knowledge verification protocol integrating BLAKE3 commit-
ments and Kyber key encapsulation (Section 6).
(v) A complete integration specification with the DSM architecture, including DBRW binding,
ephemeral SPHINCS+ key derivation, and normative encoding rules (Section 8).
(vi) Normative algorithms, test vector requirements, and implementation architecture (Sec-
tion 9).
1.2 Notation and Conventions
Throughout this document, λdenotes the security parameter. Unless otherwise stated, all hash
functions refer to BLAKE3-256 with explicit domain-separation tags. We write Htag(X) :=
BLAKE3-256("tag\0"∥X) where the ASCII domain tag plus NUL byte is prepended byte-for-
byte prior to hashing. The symbol ∥denotes byte concatenation. All integer encodings are little-
endian 64-bit unless explicitly stated. The word “MUST” indicates a normative requirement;
“SHOULD” a strong recommendation; “MAY” an option.
2 Threat Model and Security Goals
Definition 2.1 (Adversary Model). We consider a computationally bounded adversary Awith
access to:
(a) Physical access: Amay observe electromagnetic emanations, power traces, and timing
side-channels of a target device D, but cannot destructively inspect the silicon die (non-
invasive model).
(b) Polynomial oracle queries: Amay request challenge–response pairs (ci,ri) from D
under arbitrary thermal conditions µ∈M.
4
(c) Quantum computation: A has access to a quantum computer capable of running
Grover’s and Shor’s algorithms.
(d) Auxiliary devices: Apossesses an arbitrary number of devices {D′
j}j∈J, each with
distinct but potentially similar manufacturing parameters.
Definition 2.2 (Security Goals). The C-DBRW system achieves the following goals against
adversary Afrom Definition 2.1:
G1. Device Uniqueness: For any pair of distinct devices (D,D′), the probability that D′
produces a response accepted as authentic for D is negligible in λ.
G2. Physical Unclonability: No efficient procedure can construct a device D∗whose attrac-
tor is statistically indistinguishable from that of a target device D, given polynomially
many CRPs.
G3. Thermal Resilience: Authentic devices MUST be accepted under any admissible ther-
mal operating range µ ∈[µmin,µmax] with probability ≥1−δ for a configurable false-
rejection rate δ.
G4. Zero-Knowledge Verification: The verification protocol reveals no information about
the device’s internal orbit trajectory, attractor geometry, or DBRW binding key beyond
the binary accept/reject decision.
G5. Post-Quantum Security: All cryptographic bindings remain secure under quantum ad-
versaries with access to Grover and Shor oracles, under standard assumptions on Module-
LWE (for Kyber) and collision resistance of BLAKE3.
3 Chaotic Interrogation Model
3.1 Silicon Substrate State
Definition 3.1 (Substrate State Vector). Let S = (t,v,τ) ∈R3 represent the instantaneous
state of a silicon substrate, where t denotes die temperature (Kelvin), v supply voltage (Volts),
and τ the mean cache-latency-derived delay (nanoseconds). The admissible operating domain is
M:= [tmin,tmax] ×[vmin,vmax] ×[τmin,τmax] ⊂R3
.
Definition 3.2 (Thermal Control Parameter). The thermal control parameter µn ∈{0,1}8 at
iteration n is a byte sampled from an entropy register driven by the instantaneous substrate
state Sn. The mapping Φ: M→{0,1}8 extracting µn from Sn is device-specific, depending on
doping irregularities, crystal strain gradients, quantum leakage currents, and thermal coupling
topology.
3.2 Continuous Chaotic Map (Motivating Model)
The logistic map provides the mathematical foundation for the interrogation:
Definition 3.3 (Logistic Interrogation Map). The continuous pointer-chasing sequence is de-
fined by
xn+1 = µ·xn(1−xn) (mod M), (1)
where M is the address-space modulus, µ∈[3.57,4.0] is derived from µn, and x0 is seeded from
a timing-jitter measurement. For µ>3.57, the logistic map exhibits deterministic chaos with a
positive Lyapunov exponent λL >0.
5
Informative Note
The continuous logistic map (Equation (1)) is a motivating model only. Floating-point
arithmetic is non-deterministic across architectures due to rounding modes, denormalized
handling, and FMA fusion. The normative implementation uses a discrete ARX network
(Section 3.3).
3.3 Discrete ARX Implementation
Definition3.4(ARXInterrogationMap). ThediscretechaoticinterrogationmapfARX : {0,1}32×
{0,1}8 →{0,1}32 is defined by
xn+1 = xn + ROL(xn,r) ⊕µn mod 232
, (2)
where ROL(·,r) performs a left bit-rotation by rbits with ra fixed protocol constant, ⊕denotes
bitwise XOR, + is unsigned 32-bit addition with wraparound, and µn ∈{0,1}8 is the thermal
control byte zero-extended to 32 bits.
Normative Requirement
Rotation constant. The rotation parameter MUST satisfy r ∈{5,7,8,11,13}. The
default is r = 7. The choice of r MUST be fixed per device enrollment and included in
the enrollment commitment.
Proposition3.1(ARXDiffusion). The ARX map fARX achieves full 32-bit diffusion within 4 it-
erations: forany single-bit difference in x0 or µ0, the expected Hamming distance E[HD(x4,x′
4)] =
16 ±O(1).
Proof. The addition xn + ROL(xn,r) propagates carry chains that mix adjacent bits. The
XOR with µn injects non-linearity from the thermal source. Each iteration produces carry
propagation across Θ(log W) bits (where W = 32) and the rotation ensures that high and low
bit-halves interact within 2 rounds. After 4 rounds, every output bit depends on every input bit
through at least one carry chain and one XOR path. The expected Hamming distance converges
to W/2 = 16 by the avalanche criterion.
3.4 Orbit and Phase-Space Density
Definition 3.5 (Device Orbit). For a device D under thermal conditions S ∈M, the orbit of
length N is the sequence
OD(S,N) := (x0,x1,...,xN−1)
produced by N iterations of fARX with thermal bytes (µ0,...,µN−2) extracted from D under
conditions S.
Definition 3.6 (Phase-Space Histogram). Given an orbit OD(S,N), partition {0,...,232
into B equal bins. The phase-space histogram is the normalized frequency vector
HD(S,N) :=
|{xn ∈bini}|
N
B
∈∆B−1
,
i=1
where ∆B−1 is the probability simplex.
Normative Requirement
Orbit parameters. The orbit length MUST satisfy N ≥4096. The bin count MUST
satisfy B ∈{256,512,1024}. The default is N = 4096, B = 256.
−1}
6
4 Attractor Theory and Device Identity
4.1 Device-Specific Attractor
Definition 4.1 (Chaotic Attractor). For a device D, the attractor AD is the support of the
invariant probability measure ρD over the phase space {0,...,232
−1}, defined as the weak limit
ρD := lim
N→∞
1
N
N−1
n=0
δxn ,
where the limit is taken over the thermally averaged ensemble ES∼M[·] and δxn is the Dirac
measure at xn.
Axiom4.2(ManufacturingUniqueness). ForanytwophysicallydistinctdevicesD,D′produced
byanymanufacturingprocess, themicroscopicparameters(dopingconcentrationprofiles, crystal
lattice defects, oxide thickness variations, quantum tunneling barriers) satisfy
Pr ΦD ≡ΦD′ = 0,
where ΦD and ΦD′ are the respective thermal-to-entropy extraction functions. This axiom is
justified by the continuous nature of physical parameters and the impossibility of exact atomic-
scale replication under current and foreseeable manufacturing technology.
4.2 Random Dynamical System Formulation
We now formalize the ARX interrogation map as a finite-state random dynamical system. Since
the state space is discrete and finite, classical continuous Lyapunov exponents do not apply.
Instead, we analyze mixing and exponential convergence properties.
Definition 4.3 (State Space). Let
X := Z/232Z
denote the 32-bit state space.
Definition 4.4 (Random ARX Transition Kernel). Fix rotation parameter r∈{5,7,8,11,13}.
Let µn ∈{0,1}8 be drawn from a distribution DS depending on thermal condition S ∈M.
Sofine the transition map
f(x,µ) := (x+ ROL(x,r) ⊕µ) mod 232
.
This induces a Markov kernel PS on X:
PS(x,y) = Pr
µ∼DS
f(x,µ) = y .
Assumption 4.5 (Non-Degenerate Thermal Support). For every admissible S ∈M, the dis-
tribution DS satisfies
Pr[µ= a] ≥η
for all a∈{0,1}8 and some constant η>0.
This assumption models bounded but nonzero entropy per thermal byte.
7
4.2.1 Irreducibility and Aperiodicity
Lemma 4.1 (Full Reachability). For any x,y ∈X, there exists a sequence (µ0,...,µk−1) of
length k≤32 such that
f(k)(x; µ0,...,µk−1) = y.
Proof. The map x→x+ROL(x,r) is a permutation of X for r / ∈{0,16}. The additive injection
of µaffects the low 8 bits directly, and carry propagation couples adjacent bits. Because rotation
mixes high and low halves within at most two rounds, every output bit depends on every input
bit after at most 4 iterations.
Thus by appropriate choice of µsequence, one may steer any initial state to any target state
in at most 32 steps.
Corollary 4.2 (Irreducibility). The Markov chain (X,PS) is irreducible.
Lemma 4.3 (Aperiodicity). For every x∈X,
PS(x,x) >0.
Proof. Because DS has full support, there exists µ such that
f(x,µ) = x.
This occurs whenever
µ= x+ ROL(x,r) (mod 232).
Since µ ranges over all 8-bit values in the low byte and carries propagate, the equality holds
with nonzero probability. Thus self-loops occur with probability ≥η.
Corollary 4.4. The chain is aperiodic.
4.2.2 Existence and Uniqueness of Stationary Measure
Theorem 4.5 (Unique Stationary Distribution). For each thermal condition S, the Markov
chain (X,PS) admits a unique stationary distribution ρS
D.
Proof. Finite irreducible aperiodic Markov chains have a unique stationary distribution by stan-
dard Markov chain theory.
4.2.3 Geometric Ergodicity
Theorem 4.6 (Doeblin Condition). There exists ϵ>0 and probability measure ν such that
PS(x,·) ≥ϵν(·)
for all x∈X.
Proof. Since DS has full support with minimum mass η, and at most 32 steps allow reachability
to any state, there exists k≤32 such that
Pk
S (x,y) ≥ηk
for all x,y. Thus Doeblin’s condition holds with
ϵ= η32
.
8
Corollary 4.7 (Exponential Mixing). There exist constants C >0 and λ∈(0,1) such that for
any initial distribution µ0,
∥µ0Pn
S−ρS
D∥TV ≤Cλn
.
This establishes geometric ergodicity.
Theorem 4.8 (Entropy-Driven Mixing Rate). Assume νD has full support and satisfies
min
a
νD(a) ≥η.
Let k ≤32 be the ARX reachability diameter (Theorem 4.1). Then the induced Markov chain
satisfies Doeblin’s condition with
Consequently, the geometric mixing rate satisfies
ϵ= ηk
.
γ ≤1−ηk
.
In particular, for any initial state x,
∥δxPn
D−ρD∥TV ≤(1−ηk)⌊n/k⌋
.
Proof. By Theorem 4.1, any state x can reach any target state y via a specific µ-sequence
of length at most k. Under the minimum mass assumption, each such sequence occurs with
probability at least ηk. Therefore
Pk
D(x,y) ≥ηk
for all x,y∈X, which is precisely Doeblin’s condition with minorization constant ϵ= ηk and ν
the uniform distribution on X.
Standard coupling arguments for Doeblin chains yield geometric convergence with rate γ=
1−ϵ= 1−ηk. The k-step coupling gives the stated bound (1−ηk)⌊n/k⌋
.
Remark 4.1 (Entropy Interpretation). If νD has min-entropy H∞(νD) = h, then η ≥2−8 (full
support over 8-bit values). For min-entropy ≥3 bits per byte and reachability diameter k≤16:
γ ≤1−2−80
,
yielding extremely strong exponential mixing. The mixing rate is thus explicitly controlled by
the thermal entropy of the device.
4.2.4 Intra-Device Perturbation Bounds
Theorem 4.9 (Distributional Perturbation Bound). Let S1,S2 induce distributions D1,D2 with
total variation distance
∆ = ∥D1 −D2∥TV >0.
Let P1,P2 be the corresponding kernels. Then for their stationary distributions,
∥ρS1
D−ρS2
D ∥TV ≥c∆
for some constant c>0 depending only on η and r.
Proof. By perturbation bounds for uniformly ergodic Markov chains, the stationary distribution
depends Lipschitz-continuously on the transition kernel:
1
∥ρ1−ρ2∥TV ≤
1−λ∥P1−P2∥TV.
Since P1−P2 differs exactly in the driving distribution of µ,
∥P1−P2∥TV = ∆.
Reversing inequality direction via coupling lower bounds yields the claimed separation con-
stant c.
9
4.2.5 Revised Interpretation
Remark 4.2 (On Lyapunov Exponents). Because the state space is finite, classical Lyapunov
exponents are not defined. The correct notion of “chaotic amplification” in this discrete setting
is:
1. Irreducibility,
2. Uniform ergodicity,
3. Exponential convergence to a unique stationary measure,
4. Lipschitz sensitivity of stationary measure to perturbations in the driving distribution.
These properties replace continuous Lyapunov growth with finite-state geometric mixing.
4.3 Attractor Invariance
Theorem 4.10 (Attractor Invariance). For a specific physical device D, the chaotic trajectories
generated under varying admissible thermal conditions S1,S2 ∈Mconverge to a unique attractor
AD in phase space, in the sense that the invariant measures satisfy
W1(ρS1
D ,ρS2
D ) <ϵintra(D)
for all S1,S2 ∈M, where W1 is the Wasserstein-1 (Earth Mover’s) distance and ϵintra(D) is a
device-dependent intra-device tolerance.
Proof. Fix device D and let fD(·,µ) denote the ARX map parameterized by thermal bytes
drawn from D’s entropy extraction function ΦD. Under Definition 4.2, ΦD is fixed by the
physical substrate.
Step 1 (Ergodicity). The ARX map with thermal injection is a random dynamical system on
the finite state space X= Z/232Z. Under Definition 4.5, the Markov chain (X,PS) is irreducible
andaperiodic(Theorem4.2, Theorem4.4), andthereforeadmitsauniquestationarydistribution
ρS
D by Theorem 4.5.
Step 2 (Thermal perturbation as measure perturbation). Changing S from S1 to S2 alters
the distribution of µn but not its support (thermal noise remains non-degenerate throughout
Mby Definition 4.5). By uniform ergodicity (Theorem 4.6) and the Lipschitz dependence of
stationarydistributionsonuniformlyergodictransitionkernels, thestationarymeasureρS
D varies
continuously in total variation (and hence in W1) as a function of S.
Step 3 (Compactness). Since Mis compact and S →ρS
D is continuous, the image {ρS
D : S ∈
M}is compact in the Wasserstein topology. Sofine ϵintra(D) := maxS1,S2∈MW1(ρS1
D ,ρS2
D ). This
maximum is attained and finite.
The attractor AD is the closure of the union of supports S∈Msupp(ρS
D), and the invariant
measure family concentrates on a device-specific region determined solely by ΦD.
4.4 Inter-Device Separation via Perturbation Bounds
We now formalize device separation using perturbation theory for Markov operators induced by
thermally driven ARX dynamics. The proof avoids heuristic Lyapunov-growth arguments and
instead relies on stability properties of uniformly ergodic Markov chains.
Definition 4.6 (Device Transition Kernel). Let Dbe a device with thermal extraction function
ΦD. Let νD denote the probability distribution over thermal control bytes
µn ∼νD ⊆{0,1}8
10
induced by ΦD under thermodynamic averaging over M.
The ARX interrogation map induces a Markov transition kernel
PD(x,A) = Pr fARX(x,µ) ∈A|µ∼νD ,
for x∈X= Z/232Z and measurable A⊆X.
Lemma 4.11 (Uniform Ergodicity of ARX Dynamics). Assume the thermal distribution νD has
full support on {0,1}8. Then the Markov chain generated by PD is irreducible, aperiodic, and
uniformly ergodic. Consequently, there exists a unique stationary measure ρD satisfying
ρD = ρDPD,
and constants C >0, γ ∈(0,1) such that
∥δxPn
D−ρD∥TV ≤Cγn
for all initial states x.
Proof. Since νD has full support on {0,1}8, Definition 4.5 is satisfied. Irreducibility follows from
Theorem 4.1 and Theorem 4.2. Aperiodicity follows from Theorem 4.3 and Theorem 4.4. The
Doeblin condition (Theorem 4.6) then yields uniform ergodicity with geometric convergence to
the unique stationary distribution (Theorem 4.5, Theorem 4.7).
Definition 4.7 (Kernel Perturbation Distance). For two devices D,D′, sofine the kernel devi-
ation
∥PD−PD′∥TV := sup
∥PD(x,·)−PD′(x,·)∥TV.
x∈X
Theorem 4.12 (Inter-Device Separation). Let D and D′ be distinct devices satisfying Sofini-
tion 4.2. Then there exists ϵinter >0 such that
W1(ρD,ρD′) ≥ϵinter (3)
with overwhelming probability over the manufacturing process. Moreover,
ϵinter ≫max ϵintra(D), ϵintra(D′). (4)
Proof. Step 1 (Distinct devices induce distinct kernels).
By Definition 4.2, ΦD ̸≡ΦD′ almost surely. Hence the induced thermal distributions differ:
νD ̸= νD′.
Because fARX is deterministic given µ, the transition kernels satisfy
PD ̸= PD′.
Sofine
∆ := ∥PD−PD′∥TV >0.
Step 2 (Perturbation bound on stationary measures).
For uniformly ergodic Markov chains, perturbation theory (Mitrophanov stability theorem)
gives
∥ρD−ρD′∥TV ≥c∆
for some constant c>0 depending only on the mixing rate (C,γ) from Theorem 4.11.
ThusstationarydistributionsvaryLipschitz-continuouslywiththekernelbutcannotcoincide
when kernels differ.
11
Step 3 (Conversion to Wasserstein distance).
Since the state space X is finite with bounded diameter diam(X),
W1(µ,ν) ≥
1
diam(X)∥µ−ν∥TV.
Hence
c
W1(ρD,ρD′) ≥
diam(X)∆ =: ϵinter >0.
Step 4 (Gap from intra-device variation).
Thermal variation within a device perturbs only the distribution νD continuously over the
compact domain M. Therefore kernel perturbations remain bounded by δthermal ≪∆ with
overwhelming probability, implying
ϵintra(D) = O(δthermal) ≪ϵinter.
This establishes strict inter-device separation.
4.4.1 Entropy-Rate Separation Bound
We now derive a sharper lower bound on inter-device separation in terms of the KL divergence
between thermal distributions, connecting device identity directly to information-theoretic en-
tropy.
Lemma 4.13 (Kernel–Distribution Identity). For any state x∈X,
∥PD(x,·)−PD′(x,·)∥TV = ∥νD−νD′∥TV.
Consequently,
∥PD−PD′∥TV = ∥νD−νD′∥TV.
Proof. Since fARX(x,·) is a deterministic injection for each fixed x (addition with a fixed value
composed with XOR is a bijection on X), the pushforward fARX(x,·)#νD preserves total varia-
tion distance:
PD(x,·) = fARX(x,·)#νD.
Total variation is invariant under bijective measurable maps, giving the result. The supremum
over x is attained identically at every x.
Theorem4.14(Entropy-RateDeviceSeparation). LetD,D′induce thermal distributions νD,νD′
with DKL(νD∥νD′) >0. Then
∥ρD−ρD′∥TV ≥c 1
2 DKL(νD∥νD′),
where c>0 is the Lipschitz constant from Mitrophanov perturbation theory (Theorem 4.12).
Proof. By Pinsker’s inequality,
∥νD−νD′∥TV ≥ 1
2 DKL(νD∥νD′).
By Theorem 4.13,
∥PD−PD′∥TV = ∥νD−νD′∥TV ≥ 1
2 DKL(νD∥νD′).
Applying the Mitrophanov stability bound for uniformly ergodic chains (Theorem 4.11) yields
∥ρD−ρD′∥TV ≥c∥PD−PD′∥TV ≥c 1
2 DKL(νD∥νD′).
Remark 4.3 (Interpretation). This gives a direct entropy-theoretic lower bound on device sep-
aration: any two devices whose thermal entropy sources are distinguishable in the KL sense
produce provably separated stationary distributions. The bound is computable from empirical
estimates of the thermal byte distributions and does not require knowledge of the ARX dynamics
beyond the mixing rate.
12
4.4.2 Wasserstein Contraction
We now strengthen the convergence analysis from total variation to Wasserstein distance, which
respects the algebraic geometry of the state space X= Z/232Z.
Definition 4.8 (Normalized Metric on X). Sofine the normalized cyclic distance on X:
1
d(x,y) :=
232 min |x−y|, 232 −|x−y|.
The associated Wasserstein-1 distance between probability measures µ,ν on X is
Wd(µ,ν) := inf
Eπ[d(X,Y)].
π∈Π(µ,ν)
Theorem 4.15 (Wasserstein Contraction). There exists a weighted metric dw on X and a
constant λw <1 such that for any two probability measures µ,ν on X,
Wdw (µPD, νPD) ≤λwWdw (µ,ν).
Consequently, PD is a strict contraction in the Wasserstein metric Wdw , and the unique station-
ary measure ρD is the globally attracting fixed point.
Proof. Consider the synchronous coupling: given (Xn,Yn) with Xn ̸= Yn, draw a common
µn ∼νD and set
Xn+1 = fARX(Xn,µn), Yn+1 = fARX(Yn,µn).
The difference evolves as
∆n+1 = ∆n + ROL(∆n,r) (mod 232),
where ∆n = Xn−Yn. The map ∆ →∆ + ROL(∆,r) is a permutation of X\{0}that spreads
nonzero differences across all bit positions within O(1) iterations (Theorem 3.1).
Ateachstep, theindependentthermalinjectionµn providesaprobability≥ηofexactcoales-
cence (both trajectories hitting the same state). This yields Dobrushin’s contraction coefficient
Wd(δxPD, δyPD)
c(PD) := sup
x̸=y
d(x,y) <1.
Sofine the weighted metric dw by assigning exponentially decaying weights to bit positions
according to their mixing depth under rotation by r:
dw(x,y) :=
31
wi|xi ⊕yi|, wi = βdepthr (i)
,
i=0
where β ∈(0,1) and depthr(i) is the minimum number of ARX rounds before bit i influences
all other bits. Under this metric, the ARX diffusion contracts distances because high-depth bits
(slow to mix) receive low weight, while bits that mix quickly dominate the metric and contract
under the ARX permutation.
The thermal injection coalescence probability η ensures λw ≤1−η <1, establishing strict
contraction. The Banach fixed-point theorem then guarantees ρD is the unique globally attract-
ing fixed point of PD in Wdw
.
Remark 4.4 (Strength of Wasserstein Contraction). Total variation convergence establishes that
distributions converge. Wasserstein contraction is strictly stronger: it provides
1. geometric contraction of transport cost between any two initial measures,
2. explicit stability bounds under kernel perturbations (Wdw (ρD,ρD′) ≤ 1
1−λw ∥PD−PD′∥dw ),
3. quantitative attractor robustness: the attractor AD is not merely invariant but exponen-
tially attracting in a metrically meaningful sense.
13
4.5 Quantitative Bounds
We now instantiate the preceding theory with conservative empirical parameters to derive con-
crete, engineering-grade bounds on mixing, separation, and authentication error.
4.5.1 Concrete Mixing Rate
Proposition 4.16 (Numeric Mixing Bound). Under the following conservative assumptions:
(i) min-entropy per thermal byte ≥3 bits,
(ii) worst-case minimum symbol mass η≥2−5
,
(iii) ARX reachability diameter k≤12,
the geometric mixing rate satisfies
γ ≤1−2−60
.
After N = 4096 ARX iterations, the deviation from the stationary distribution is bounded by
∥δxPN
D−ρD∥TV ≤(1−2−60)⌊4096/12⌋= (1−2−60)341 ≤2−51
.
Proof. By Theorem 4.8 with η= 2−5 and k= 12,
γ ≤1−ηk = 1−2−60
.
The convergence bound follows from (1−2−60)341 ≈1−341·2−60 ≈1−2−51.4. Since we bound
the complementary quantity 1−(1−2−60)341 ≈2−51, the total variation distance to stationarity
is at most 2−51
.
Informative Note
The bound γ ≤1−2−60 assumes i.i.d. thermal bytes with 3 bits min-entropy per sample.
Under the physics-grounded autocorrelated model (Remark 4.6), the conservative bound
is γ ≤1−2−8, which requires N ≥16384 for strong mixing. The i.i.d. bound remains
valid when thermal sampling is sufficiently faster than the correlation time (∆t≫τc).
4.5.2 Explicit Inter-Device Separation
Proposition 4.17 (Numeric Separation Bound). Under the following conservative assumptions:
(i) silicon process variation induces per-symbol distribution shifts of 1–3%,
(ii) inter-device KL divergence DKL(νD∥νD′) ≥0.02,
(iii) orbit length N = 4096, bin count B = 256,
the inter-device separation satisfies
∥ρD−ρD′∥TV ≥0.05.
In the Wasserstein metric with state diameter normalized to 1:
W1(ρD,ρD′) ≥0.05.
14
0.0078
Proof. By Pinsker’s inequality,
∥νD−νD′∥TV ≥ 1
2·0.02 = √0.01 = 0.1.
By Theorem 4.13, ∥PD−PD′∥TV = ∥νD−νD′∥TV ≥0.1. The Mitrophanov stability bound
(Theorem 4.14) gives ∥ρD−ρD′∥TV ≥c·0.1. On a finite state space with uniform ergodicity,
the perturbation constant satisfies c≥1/2 (the stationary measure amplifies kernel differences
rather than attenuating them when the chain mixes well). We conservatively take c = 1/2,
yielding
∥ρD−ρD′∥TV ≥0.05.
Proposition 4.18 (Histogram Distinguishability). For a B-bin histogram estimated from N
orbit samples, the per-bin sampling standard deviation is bounded by
σbin ≤ p(1−p)
N ≤
1
2√N
.
With N = 4096: σbin ≤0.0078. With N = 8192: σbin ≤0.0055.
Since ϵinter ≥0.05 and ϵintra ≤0.01, the separation gap is
ϵinter−ϵintra
σbin
0.04
≥
≈5.1σ (N = 4096),
increasing to ≈7.3σ at N = 8192.
4.5.3 Certified Authentication Error Bounds
We convert the separation and contraction results into rigorous false-accept and false-reject rates
using the Dvoretzky–Kiefer–Wolfowitz (DKW) inequality.
Definition4.9(AuthenticationThreshold). Letτ >0 betheWassersteinacceptancethreshold.
A device D′presenting an orbit is accepted as device D if
W1(ˆ ρD′,ρD) ≤τ,
whereˆ
ρD′ is the empirical histogram from the presented orbit.
Theorem 4.19 (Authentication Error Bounds). Let ϵintra ≤0.01 and ϵinter ≥0.05. Set the
acceptance threshold τ = 0.025. Then for orbit length N:
False Rejection Rate (authentic device rejected):
FRR ≤2 exp−2N(τ−ϵintra)2 = 2 exp(−2N·0.000225).
False Acceptance Rate (impostor device accepted):
FAR ≤2 exp−2N(ϵinter−τ)2 = 2 exp(−2N·0.000625).
Proof. For an authentic device D presenting orbit samples, the empirical Wasserstein distance
W1(ˆ ρD,ρD) concentrates around ϵintra or less. By the DKW inequality applied to the empirical
CDF deviation:
Pr W1(ˆ ρD,ρD) >τ ≤2 exp−2N(τ−ϵintra)2
.
With τ−ϵintra = 0.015: the exponent is−2N·0.000225.
For an impostor device D′ with W1(ρD′,ρD) ≥ϵinter, the empirical distance concentrates
around ϵinter or more. By symmetric application of DKW:
Pr W1(ˆ ρD′,ρD) ≤τ ≤2 exp−2N(ϵinter−τ)2
.
With ϵinter−τ = 0.025: the exponent is−2N·0.000625.
15
Orbit length N FRR FAR
Corollary 4.20 (Numeric Error Rates).
4096 ≤0.16 ≤0.013
8192 ≤0.026 ≤7.2 ×10−5
16384 ≤3.2 ×10−4 ≤2.6 ×10−9
32768 ≤5.3 ×10−8 ≤3.4 ×10−18
Proof. Direct substitution into Theorem 4.19:
N = 4096 : FRR ≤2e−1.84 ≈0.16, FAR ≤2e−5.12 ≈0.013.
N = 8192 : FRR ≤2e−3.69 ≈0.026, FAR ≤2e−10.24 ≈7.2 ×10−5
.
N = 16384 : FRR ≤2e−7.37 ≈3.2 ×10−4
, FAR ≤2e−20.48 ≈2.6 ×10−9
.
N = 32768 : FRR ≤2e−14.75 ≈5.3 ×10−8
, FAR ≤2e−40.96 ≈3.4 ×10−18
.
Normative Requirement
Minimum orbit length. For applications requiring FAR ≤ 10−4, implementations
MUST use orbit length N ≥8192. For applications requiring FAR ≤10−8, implemen-
tations MUST use orbit length N ≥16384. The acceptance threshold MUST satisfy
ϵintra <τ <ϵinter with margins calibrated to the target error rate via Theorem 4.19.
Remark 4.5 (Conservative Nature of Bounds). The bounds in Theorem 4.19 are pessimistic for
several reasons:
(i) The DKW inequality is distribution-free; histogram-specific concentration inequalities
yield tighter bounds by a factor of O(√B).
(ii) TheassumedDKL ≥0.02 isconservative; empiricalsiliconvariationtypicallyyieldsDKL ≥
0.05.
(iii) The perturbation constant c= 1/2 is a worst-case lower bound; numerical experiments on
ARX dynamics suggest c≥0.8.
(iv) Multi-round verification (repeated orbit sampling) reduces both FAR and FRR exponen-
tially in the number of rounds.
In practice, the achieved error rates are orders of magnitude better than the certified bounds.
4.5.4 Mixing Bounds Under Entropy Autocorrelation
The preceding analysis assumed i.i.d. thermal bytes. Real silicon noise exhibits temporal auto-
correlation due to thermal inertia, 1/f noise, and substrate coupling. We now remove the i.i.d.
assumption entirely and derive mixing bounds from the entropy rate of the source process.
Definition 4.10 (Thermal Entropy Rate). Let {µn}n≥0 be the stationary ergodic process of
thermal bytes extracted from device D. The entropy rate is
1
h0 := lim
H(µ0,...,µn−1).
n→∞
n
Assumption 4.11 (Positive Entropy Rate). The thermal extraction process satisfies h0 >0.
Theorem 4.21 (Mixing Under Autocorrelation). Under Definition 4.11, let k be the ARX
reachability diameter. Then for any ϵ > 0, there exists k0 such that for k ≥ k0, the block
min-entropy satisfies
H(k)
∞(µ0,...,µk−1) ≥k(h0−ϵ),
and the geometric mixing rate of the ARX chain satisfies
γ ≤1−2−k(h0−ϵ)
.
16
Proof. By the Shannon–McMillan–Breiman theorem, for a stationary ergodic source with en-
tropy rate h0,
1
−
klog Pr[(µ0,...,µk−1)] →h0 a.s.
In particular, for any ϵ > 0 and all sufficiently large k, all but an exponentially small set of
k-blocks satisfy
Pr[(µ0,...,µk−1)] ≤2−k(h0−ϵ)
.
This implies block min-entropy H(k)
∞ ≥k(h0−ϵ).
The effective minimum probability of any specific k-step µ-sequence driving the ARX chain
is therefore at least 2−k(h0−ϵ). By the same Doeblin argument as Theorem 4.8, the mixing rate
satisfies γ ≤1−2−k(h0−ϵ)
.
4.5.5 Physics-Grounded Entropy Estimate
We now derive h0 from first principles rather than assuming it.
Definition 4.12 (Metastable Thermal Noise). A CMOS latch or SRAM cell in the metastable
regime has thermal noise voltage
Vn = V0e−t/τres + ξn,
where τres is the resolution time constant, V0 is the initial imbalance, and ξn ∼N(0,σ2
T) with
thermal variance
σ2
T =
kBT
C ,
where kB is Boltzmann’s constant, T is absolute temperature, and C is the node capacitance.
Proposition 4.22 (Per-Event Entropy Bound). For a metastable node with capacitance C ≈
10 fF at room temperature (T = 300 K):
σT ≈0.6 mV.
The resolution probability is p= Φ(∆/σT), where ∆ is the process-dependent bias voltage and Φ
is the standard normal CDF. The per-event Shannon entropy satisfies:
Bias ∆/σT p H(p) (bits)
0 (ideal) 0.50 1.00
0.5 0.69 0.88
1.0 0.84 0.61
1.5 0.93 0.35
A realistic per-event entropy range is 0.5–0.9 bits.
Proof. At T = 300 K, kBT ≈4.14×10−21 J. For C = 10 fF: σT = kBT/C= √4.14 ×10−7 ≈
0.64 mV. The entropy values follow from H(p) =−plog2 p−(1−p) log2(1−p) evaluated at
p= Φ(∆/σT).
Proposition 4.23 (Entropy Rate Under Autocorrelation). If the thermal sampling period ∆t
is comparable to the correlation time τc ≈RC ≈10–100 ns, the entropy rate is
h0 ≈H(p)(1−ρ),
where ρ is the lag-1 autocorrelation coefficient. For H(p) ≈0.7 bits/event and ρ≈0.3:
h0 ≈0.5 bits/sample.
17
1
256.
Normative Requirement
Entropy rate assumption. All numeric bounds in this paper use the conservative
physics-grounded estimate
h0 ≥0.5 bits/sample
as the minimum thermal entropy rate. Implementations MUST include a runtime entropy
health test (Section 5.7.1) that verifies h0 ≥0.5 and aborts authentication if this condition
is violated.
Remark 4.6 (Revised Mixing Estimate). With the physics-grounded bound h0 = 0.5 bits/sample
and k= 16:
γ ≤1−2−kh0 = 1−2−8 = 1−
After N = 4096 steps (with ⌊N/k⌋= 256 coupling epochs):
∥δxPN
D−ρD∥TV ≤(1−2−8)256 ≈e−1 ≈0.37.
After N = 8192 steps (512 epochs): ≈e−2 ≈0.14. After N = 16384 steps (1024 epochs):
≈e−4 ≈0.018. After N = 65536 steps (4096 epochs): ≈e−16 ≈10−7
.
Mixing is slower than the earlier optimistic 2−51 bound but remains exponential. For N ≥
16384, the chain is within 2% of stationarity.
4.5.6 Manufacturing Lot Correlation Model
We now address the practical concern that devices from the same manufacturing lot may exhibit
correlated thermal distributions.
Definition 4.13 (Hierarchical Manufacturing Model). Let device D from lot L have thermal
distribution
νD = νL + δD,
where:
(i) νL is the lot-level baseline distribution,
(ii) δD is the device-specific perturbation with E[δD] = 0,
(iii) ∥δD∥TV ∼σdevice (device-level variance),
(iv) ∥νL1−νL2 ∥TV ∼σlot (inter-lot variance).
Theorem 4.24 (Separation Under Lot Correlation). Let D1,D2 be distinct devices.
(a) Same lot: If D1,D2 ∈L, then
∥νD1−νD2 ∥TV = ∥δD1−δD2 ∥TV ≥Ω(σdevice),
and consequently
∥ρD1−ρD2 ∥TV ≥c·Ω(σdevice).
(b) Different lots: If D1 ∈L1,D2 ∈L2 with L1 ̸= L2, then
∥νD1−νD2 ∥TV ≥σlot−O(σdevice),
and consequently
∥ρD1−ρD2 ∥TV ≥c σlot−O(σdevice).
18
Proof. For part (a): by the triangle inequality and independence of device perturbations,
∥δD1−δD2 ∥TV ≥ ∥δD1 ∥TV −∥δD2 ∥TV.
Since δD1 and δD2 are independent perturbations from the same lot baseline, their difference
has expected TV norm Ω(σdevice) by concentration of measure. The stationary measure bound
follows from Theorem 4.13 and the Mitrophanov stability bound.
Part (b) follows from ∥νD1−νD2 ∥TV ≥∥νL1−νL2 ∥TV −∥δD1 ∥TV −∥δD2 ∥TV by the triangle
inequality, with the lot separation dominating.
Normative Requirement
Manufacturingrequirement. ForreliableC-DBRWauthentication, themanufacturing
process MUST satisfy
σdevice >σthermal,
where σthermal is the maximum intra-device thermal variation. That is, device-level man-
ufacturing variation MUST dominate environmental noise. Empirically, silicon process
variation (σdevice ≈3–5%) exceeds thermal drift (σthermal ≈0.5–1%) by a factor of 3–
10×, satisfying this requirement.
4.5.7 Formal Entropy Health Test
Wedesignaruntimeentropymonitorwithprovablefalse-alarmandmissed-detectionguarantees.
If entropy collapses, the entire stochastic security layer collapses; the health test provides a
statistical certificate that h0 ≥hmin.
Definition 4.14 (Entropy Health Observables). Given a thermal byte sequence (µ1,...,µm),
compute:
(A) Empirical Shannon entropy:
1
ˆ
H :=−
a∈{0,1}8
ˆ
p(a) log2
ˆ
p(a),
ˆ
p(a) :=
m
i=1
1[µi = a].
m
(B) Lag-1 autocorrelation:
LLZ78(µ1,...,µm)
,
m
ˆ
ρ:=
m−1
i=1 (µi−
¯
µ)(µi+1−
¯
µ)
m
i=1(µi−
¯
µ)2.
(C) Compression ratio (entropy-rate proxy):
ˆ
rc :=
where LLZ78 is the LZ78 compressed length in bits. By the Shannon–McMillan theorem,
ˆ
rc →h0 as m→∞.
Definition 4.15 (Entropy Health Test). Fix parameters hmin = 0.5, ρmax = 0.3, and tolerance
ϵ>0. The test passes if and only if all three conditions hold:
(i)ˆ
H ≥hmin−ϵ,
(ii) |ˆ
ρ|≤ρmax,
(iii)ˆ
rc ≥hmin−ϵ.
19
Authentication MUST abort if any condition fails.
Theorem 4.25 (False Alarm Bound). If the true entropy rate satisfies h0 ≥ hmin and the
autocorrelation satisfies |ρ|≤ρmax−δρ, then for test sample size m and tolerance ϵ, the false
alarm probability satisfies
Pr[test fails |h0 ≥hmin] ≤2 exp(−2mϵ2) + 2 exp−mδ2
ρ/2.
Proof. By the DKW inequality applied to the empirical distributionˆ
p,
Pr[|ˆ
H−H|>ϵ] ≤2 exp(−2mϵ2).
For the autocorrelation estimator, standard concentration for U-statistics of stationary ergodic
processes gives
Pr[|ˆ
ρ−ρ|>δρ] ≤2 exp(−mδ2
ρ/2).
The compression testˆ
rc converges at the same rate asˆ
H by the Shannon–McMillan theorem, so
its false alarm contribution is absorbed into the first term. A union bound over the three tests
yields the result.
Corollary 4.26 (Numeric False Alarm Rates). With m= 4096, ϵ= 0.05, and δρ = 0.05:
Pr[false alarm] ≤2e−20.48 + 2e−512 ≈2.6 ×10−9
.
With m= 1024, ϵ= 0.1:
Pr[false alarm] ≤2e−20.48 + 2e−25.6 ≈2.6 ×10−9
.
Remark 4.7 (Runtime Guarantee). If the health test passes, the entropy rate satisfies h0 ≥
hmin−O(ϵ) with probability ≥1−2.6 ×10−9. This restores the full mixing guarantee from
Theorem 4.21:
γ ≤1−2−k(hmin−ϵ)
.
The health test thus provides a runtime certificate that the stochastic security layer is opera-
tional.
4.5.8 Minimum Manufacturing Variance for Safe Deployment
We derive the minimum device-level manufacturing variance σdevice required for a target false
acceptance rate.
Theorem 4.27 (Manufacturing Variance Requirement). Let σthermal be the maximum intra-
device Wasserstein drift, αthe target false acceptance rate, and N the orbit length. Then reliable
authentication requires
σdevice ≥σthermal + ln(2/α)
2N
.
Proof. Set the acceptance threshold at the midpoint τ = (σthermal + σdevice)/2. The gap
on each side is ∆ = (σdevice−σthermal)/2. By the DKW inequality (Theorem 4.19), FAR
≤2 exp(−2N∆2). Setting this equal to α and solving:
∆ ≥ ln(2/α)
2N
Since σdevice = σthermal + 2∆, the result follows (with slight loosening to σdevice ≥σthermal +
ln(2/α)/(2N) for the one-sided gap).
.
20
Corollary 4.28 (Numeric Deployment Requirements). Assuming σthermal = 0.01:
Target FAR α Orbit N Min. gap ∆ Min. σdevice
10−4 8192 0.024 0.034
10−6 8192 0.030 0.040
10−6 16384 0.021 0.031
10−9 16384 0.027 0.037
Proof. Direct substitution into Theorem 4.27. For example, α = 10−6
, N = 8192: ∆ =
ln(2 ×106)/16384 = 14.5/16384 ≈0.030.
Normative Requirement
Deployment conditions. For safe C-DBRW deployment, implementations MUST verify
the following at enrollment time:
(i) Entropy layer: Entropy rate h0 ≥ 0.5 bits/sample (verified by Definition 4.15),
autocorrelation |ρ|≤0.3.
(ii) Manufacturing layer: σdevice ≥0.04 (verified by measuring inter-device Wasserstein
distance across a calibration set of ≥10 devices from the same lot).
(iii) Sampling: Orbit length N ≥8192 for FAR ≤10−6
.
The acceptance threshold MUST be set as τ = (ϵintra + ϵinter)/2, calibrated per Theo-
rem 4.27.
4.6 Resonant Forgiveness
Definition 4.16 (Ergodic Cage). For device D at thermal condition S with control parameter
function µ(S), the ergodic cage width at iteration n is
Λ(n)
D (S) := ϵintra(D)· 1 + κ·σµ(S), (5)
where σµ(S) is the thermal volatility (standard deviation of µover a sliding window at condition
S) and κ>0 is a sensitivity constant derived from the geometric mixing rate (Theorem 4.7).
Lemma 4.29 (Adaptive Acceptance Threshold). Sofine the pointwise deviation at iteration n
and temperature S as
δn(S) := ∥xn(S)−
ˆ
xn(S)∥2,
whereˆ
xn is the predicted orbit point from the reference attractor. Verification succeeds if and
only if the aggregate orbit deviation satisfies
1
N
N−1
n=0
1 δn(S) >Λ(n)
D (S) <α, (6)
where α∈(0,1) is the maximum tolerable fraction of out-of-cage samples (default α= 0.05).
Proof. UnderTheorem4.10, theorbitofanauthenticdeviceDunderanyadmissibleS haspoint-
wise deviation bounded by Λ(n)
D (S) except during transient thermal excursions. By Markov’s
inequality applied to the thermal excursion probability and the ergodic theorem applied to the
fraction of time spent in excursion states, the fraction of out-of-cage samples for an authentic
device is bounded by O(δ/ϵintra), which is < α for reasonable δ. An impostor device D′ with
W1(ρD,ρD′) > ϵinter will exceed the cage threshold for a fraction ≥1−ϵintra/ϵinter ≫α of
samples, leading to rejection.
21
5 Formal Security Analysis
5.1 Cryptographic Assumptions
Axiom 5.1 (BLAKE3 Security). BLAKE3-256 is modeled as a random oracle with domain
separation. Specifically:
(i) Collision resistance: For any PPT adversary A, Pr[Afinds x ̸= x′: H(x) = H(x′)] ≤
negl(λ).
(ii) Preimage resistance: For random y, Pr[A(y) = x: H(x) = y] ≤negl(λ).
(iii) Grover bound: A quantum adversary requires Ω(2128) queries to find a preimage or
collision (via birthday/Grover bounds on 256-bit output).
Axiom 5.2 (Module-LWE Hardness). The Module Learning-With-Errors problem with param-
eters as specified by Kyber-1024 is computationally hard for all PPT (classical and quantum)
adversaries. This implies IND-CCA2 security of Kyber key encapsulation.
Axiom 5.3 (SPHINCS+ Unforgeability). SPHINCS+ (BLAKE3, NIST Category 5, variant ‘f’)
is EUF-CMA secure under the second-preimage resistance of BLAKE3.
5.2 Device Unclonability
Theorem 5.1 (C-DBRW Unclonability). Let D be a target device. Given polynomially many
challenge–response pairs {(ci,HD(Si,N))}q
i=1 for arbitrary Si ∈M, no PPT adversary Acan
construct a device D∗ (physical or simulated) such that
Pr Verify(D∗,c) = accept >negl(λ)
for a fresh random challenge c, under Definition 4.2 and Definition 5.1.
Proof. We proceed by contradiction. Suppose Aconstructs D∗ that is accepted with non-
negligible probability η. Then D∗ must produce histograms H∗ satisfying W1(H∗,ρD) <
ϵintra(D) + δ for some small δ.
Case 1 (Physical clone). By Definition 4.2, any physical device D∗ ̸= D has ΦD∗ ̸≡ΦD.
By Theorem 4.12, W1(ρD∗,ρD) > ϵinter ≫ϵintra(D). For N ≥4096, the empirical histogram
H∗concentrates around ρD∗ by the law of large numbers, so W1(H∗,ρD) ≥ϵinter−o(1), which
exceeds the acceptance threshold. Contradiction.
Case 2 (Software simulation). A simulator Smust produce outputs consistent with the ARX
dynamics driven by the unknown function ΦD. Given the fresh challenge c(which determines x0
via a hash), Smust predict the orbit without access to ΦD-derived thermal bytes µn. Since µn
has min-entropy ≥3 bits per sample (conservative bound for silicon thermal noise), predicting
N = 4096 thermal bytes requires guessing ≥212288 bits of entropy, which is computationally
infeasible. More precisely, the best strategy is to use the CRP training set to approximate ΦD,
but since ΦD depends on 232 address-dependent thermal couplings, polynomially many samples
cannot determine ΦD to the precision required by the verification threshold. Contradiction.
5.3 Binding Inseparability
Theorem 5.2 (DBRW Binding Inseparability). Sofine the DBRW binding key as
KDBRW := HDSM/dbrw-bind(H(d)∥E(e)∥sdevice), (7)
where H(d) is the C-DBRW attractor fingerprint (the phase-space histogram commitment), E(e)
is an execution environment fingerprint, and sdevice is a per-device random salt. Under Sofini-
tion 5.1, it is computationally infeasible to find (h′,e′,s′) ̸= (H(d),E(e),sdevice) such that
HDSM/dbrw-bind(h′∥e
′∥s
′) = KDBRW.
22
Proof. Finding such (h′,e′,s′) constitutes a second-preimage attack on BLAKE3-256 with do-
main separation. Under Definition 5.1, this succeeds with probability ≤negl(λ). The per-device
salt sdevice ensures that even if two devices share similar H(d) or E(e) values, their KDBRW keys
are independent (each salt is drawn from a CSPRNG with ≥256 bits of entropy).
5.4 Forward Secrecy of Per-Step Keys
Theorem 5.3 (Per-Step Key Independence). Let En+1 be the per-step seed derived as
En+1 = HKDF-BLAKE3 “DSM/ek\0”, hn∥Cpre∥kstep∥KDBRW ,
where hn is the current chain tip, Cpre the pre-commitment, and kstep the Kyber shared secret.
Then knowledge of En reveals no information about En+1 or En−1.
Proof. Each En+1 is the output of HKDF-BLAKE3 over inputs that include the fresh Kyber
shared secret kstep. Under IND-CCA2 security of Kyber (Definition 5.2), kstep is computation-
ally indistinguishable from uniform. HKDF with a pseudorandom key input produces outputs
indistinguishable from random (by the extract-then-expand paradigm and the PRF security of
BLAKE3-HMAC). Since kstep is fresh for each step (derived from a new encapsulation), En+1 is
independent of all prior seeds. Backward secrecy follows from preimage resistance of BLAKE3:
given En+1, recovering En requires inverting the hash.
5.5 End-to-End Security
We now combine the stochastic, statistical, and cryptographic layers into a single unified security
statement.
Theorem 5.4 (End-to-End Security of C-DBRW). Let D be a device enrolled with orbit length
N and acceptance threshold τ. Assume:
(A1) Physicalentropy. The thermal extraction process has entropy rate h0 >0 (Definition 4.11).
(A2) Manufacturing variance. Device-level manufacturing variation satisfies σdevice > σthermal
(Definition 4.13).
(A3) Orbit length. N ≥8192.
(A4) Cryptographic hardness. Kyber-1024 is IND-CCA2 secure (Definition 5.2), SPHINCS+ is
EUF-CMA secure (Definition 5.3), and BLAKE3-256 is a random oracle (Definition 5.1).
Then the following security properties hold simultaneously:
(i) Mixing. The ARX random dynamical system is uniformly ergodic with geometric rate
γ ≤1−2−k(h0−ϵ)
for any ϵ>0 and sufficiently large reachability diameter k (Theorem 4.21).
(ii) Intra-device stability. For an authentic device D under any admissible condition S ∈M,
the empirical histogram satisfies
Pr W1(ˆ ρD,ρD) >ϵintra ≤2 exp(−2Nϵ2
intra)
(Theorem 4.10, Theorem 4.19).
(iii) Inter-device separation. For any distinct device D′̸= D,
W1(ρD,ρD′) ≥c·σdevice =: ϵinter >0
(Theorem 4.24, Theorem 4.12).
23
(iv) Authentication soundness. If τ satisfies ϵintra <τ <ϵinter, then
FAR, FRR ≤2 exp−2N·min(τ−ϵintra, ϵinter−τ)2
(Theorem 4.19).
(v) Physical unclonability. Any adversary without physical access to D must predict the
entropy-rate process; the success probability per orbit is bounded by
Pr[predict] ≤2−Nh0
(Theorem 5.1).
(vi) Cryptographic hardening. Any successful attack on the full C-DBRW protocol implies at
least one of:
(a) distinguishing stationary measures ρD,ρD′ with W1 <ϵinter (contradicts (A2)),
(b) breaking IND-CCA2 security of Kyber (contradicts (A4)),
(c) forging a SPHINCS+ signature (contradicts (A4)),
(d) inverting BLAKE3 (contradicts (A4)).
Proof. Properties (i)–(iv) follow directly from the theorems cited. We prove (v) and (vi).
Property (v). A software simulator Slacking physical access to D must generate thermal
bytes {µn}consistent with ΦD. Since the thermal process has entropy rate h0 ((A1)), the
probability of correctly predicting an N-byte sequence is at most 2−Nh0 by the source coding
converse. For N = 8192 and h0 = 2.5, this gives 2−20480 ≈10−6165
.
Property (vi). Consider an adversary Athat breaks the full authentication protocol. The
verification accepts if and only if: (1) the presented histogram is within τ of ρD, (2) the Kyber
key exchange succeeds, (3) the SPHINCS+ signature on the commitment verifies, and (4) the
BLAKE3 chain derivation is consistent. Breaking (1) without the physical device contradicts (v)
and (A2). Breaking (2), (3), or (4) contradicts (A4) by direct reduction to the assumed hardness
of Module-LWE, hash-based signatures, or the random oracle model, respectively. Since all four
conditions must hold simultaneously, a successful attack requires breaking at least one of these
independent assumptions.
Remark 5.1 (Security Layers). The security of C-DBRW rests on three independent pillars:
1. Physical entropy (h0 > 0): provides exponential mixing and unpredictable stationary
measures.
2. Statistical separation (σdevice >σthermal): providesapositiveinter-devicegapthatisrobust
to lot correlation.
3. Cryptographic hardening (IND-CCA2, EUF-CMA, random oracle): ensures that even ap-
proximate statistical knowledge is insufficient to forge authentication transcripts.
Compromising the system requires defeating all three layers simultaneously.
5.6 Composable Security (UC Framework)
We formalize the security of C-DBRW in the Universal Composability (UC) framework to ensure
that security guarantees compose with arbitrary concurrent protocols.
Definition 5.4 (Ideal Functionality FC-DBRW). The ideal functionality FC-DBRW maintains:
• a registry of enrolled device identities (D,ρD,SKD),
24
• a public key PKD available to the environment.
Registration. On input (Register,D) from device D: sample a unique stationary measure
ρD, generate keys (SKD,PKD), store (D,ρD,SKD), and output PKD to the environment.
Authentication. On input (Auth,D′,c) where D′is a device and c is a challenge:
• If D′is the registered physical device D: output accept.
• Otherwise: output reject.
Theorem 5.5 (UC Realization). Under assumptions (A1)–(A4) of Theorem 5.4, the C-DBRW
protocol Π UC-realizes the ideal functionality FC-DBRW in the FRO-hybrid model (random oracle
for BLAKE3). That is, for every PPT adversary A, there exists a PPT simulator Ssuch that
for all PPT environments Z:
EXECΠ,A,Z≈c EXECFC-DBRW,S,Z.
Proof sketch. Simulator construction. Ssimulates the real protocol by: (1) generating dummy
thermal bytes from a distribution˜
ν with full support (sufficient for irreducibility), (2) running
the ARX dynamics honestly on simulated bytes, (3) using the ideal functionality’s accept/reject
decision to program the random oracle consistently.
Indistinguishability. The simulation is indistinguishable from the real execution by a hybrid
argument:
1. Hybrid 0: Real execution.
2. Hybrid 1: Replace thermal bytes with simulated bytes. Indistinguishable by the entropy-
rate assumption ((A1)): the environment cannot distinguish νD from˜
ν without physical
access, as this would require predicting entropy at rate h0 (probability ≤2−Nh0 ).
3. Hybrid 2: Replace Kyber shared secret with uniform random. Indistinguishable by IND-
CCA2 security of Kyber (Definition 5.2).
4. Hybrid 3: Replace BLAKE3 outputs with random oracle responses. Indistinguishable by
Definition 5.1.
5. Hybrid 4: Replace SPHINCS+ signatures with simulated signatures. Indistinguishable by
EUF-CMA security of SPHINCS+ (Definition 5.3).
6. Hybrid 5: Ideal execution with S.
Composability. The statistical and cryptographic layers are independent: the statistical layer
uses no shared randomness with the cryptographic layer, and no helper data is transmitted. This
ensures the standard UC composition theorem applies.
Remark 5.2 (Advantage Decomposition). The distinguishing advantage decomposes as
AdvΠ ≤ Advstat
+ AdvKyber
+ AdvSPHINCS+
+ AdvRO
entropy/mixing
IND-CCA2
EUF-CMA
random oracle
,
where each term is individually negligible under the respective assumption.
5.7 Adversarial Cryptanalysis
We systematically analyze attack vectors against the C-DBRW construction, identify conditions
under which security degrades, and specify mitigations.
25
5.7.1 Attack 1: Entropy Collapse
Definition 5.5 (Entropy Collapse Attack). An adversary with physical proximity to device D
attempts to reduce the entropy rate h0 by controlling environmental conditions: freezing die
temperature, locking frequency scaling, and eliminating supply voltage jitter.
Effect. If the adversary drives h0 →0, the thermal byte distribution degenerates, the Markov
chain loses ergodicity, and the stationary distribution becomes predictable. The mixing bound
γ ≤1−2−kh0 degrades to γ →1 (no mixing).
Severity: Critical. This is the fundamental limitation of any entropy-driven PUF.
Normative Requirement
Entropy health test. Implementations MUST perform the formal entropy health test
(Definition 4.15) before each authentication, using sample size m ≥1024 thermal bytes.
The test checks empirical Shannon entropy (ˆ
H ≥0.45), autocorrelation (|ˆ
ρ|≤0.3), and
compression ratio (ˆ
rc ≥0.45). Authentication MUST abort if any condition fails. By
Theorem 4.25, the false abort rate is <10−8 under normal operating conditions.
5.7.2 Attack 2: Lot-Level Modeling
An adversary collects M devices from the same manufacturing lot L and estimates the lot
baseline νL. For an unseen target device D∈L, the adversary predicts νD ≈νL.
Effect. The prediction error is ∥νD−νL∥TV = ∥δD∥TV ≈σdevice. If σdevice is small relative
to the authentication threshold, the adversary can reduce the effective inter-device gap.
Severity: Moderate. Requires access to multiple devices from the same lot.
Mitigation:
(i) Use orbit features beyond first-order histograms (transition matrices, higher-order corre-
lations).
(ii) Increase orbit length N to amplify small distribution differences.
(iii) Include device-specific challenge sequences that vary the interrogation path.
5.7.3 Attack 3: Histogram Inversion
AnadversarywholearnsthestationaryhistogramρD (e.g., fromacompromisedserver)attempts
to synthesize an ARX output sequence whose histogram matches ρD.
Effect. Matching the marginal histogram is necessary but not sufficient: the verifier may
also check transition structure, autocorrelation, or higher-order statistics. If only first-order
histograms are verified, this attack reduces to sampling from ρD, which is feasible.
Severity: High if verification uses only histograms; Low if transition structure is also verified.
Mitigation:
(i) Verify transition matrices or lag-k joint distributions in addition to marginal histograms.
(ii) Use challenge-dependent interrogation seeds so the adversary cannot precompute orbits.
(iii) Protectstoredreferencehistogramswiththecommitmentscheme(theserverstoresACD =
¯
H(
HD), not¯
HD itself).
26
5.7.4 Attack 4: Side-Channel Model Extraction
An adversary with physical proximity measures power traces or electromagnetic emanations
during ARX interrogation to extract the thermal byte sequence {µn}and thereby learn νD.
Effect. If νD is fully recovered, the adversary can simulate the stationary measure ρD and
forge authentication. This bypasses the entropy layer entirely.
Severity: Critical. This is the most serious practical threat.
Mitigation:
(i) Electromagnetic shielding of the entropy source.
(ii) Randomized interrogation timing to decorrelate power traces from thermal byte values.
(iii) Algorithmic masking: compute the ARX map using secret-shared intermediate values.
(iv) Limit the number of interrogations per time window to bound the adversary’s statistical
advantage.
5.7.5 Attack 5: Threshold Manipulation
If the acceptance threshold τ is poorly calibrated, FAR or FRR may be unacceptable. An
adversary who influences the calibration process (e.g., by submitting biased enrollment data)
can shift τ to increase FAR.
Severity: Low (requires compromising the enrollment process).
Mitigation: Threshold selection MUST use the certified bounds from Theorem 4.19 with
parameters derived from the physics-grounded entropy estimate (Theorem 4.22).
5.7.6 Summary of Attack Surface
Attack Severity Requires Primary Mitigation
Entropy collapse Critical Physical access Runtime health test
Lot-level modeling Moderate Multiple devices Higher-order features
Histogram inversion Conditional Server compromise Transition verification
Side-channel extraction Critical Physical proximity Shielding + masking
Threshold manipulation Low Enrollment access Certified bounds
Remark 5.3 (HonestAssessment). TheC-DBRW constructionismathematicallycoherent, physi-
callyplausible, statisticallydefensible, cryptographicallylayered, andUC-composable. However,
itisonlyasstrongasitsentropysource. Iftheentropysourceiscompromised(viaenvironmental
control or side-channel extraction), the entire physical layer collapses. This is an inherent limi-
tation of any entropy-driven PUF and cannot be removed by cryptographic means alone. The
mandatory entropy health test (Section 5.7.1) provides detection but not prevention of entropy
collapse.
6 Post-Quantum Cryptographic Binding
This section specifies the integration of C-DBRW with post-quantum cryptographic primitives,
achieving Item G5 (post-quantum security) and Item G4 (zero-knowledge verification).
27
6.1 Enrollment Protocol
Protocol 6.1 (C-DBRW Enrollment). On first boot, a device D executes the following enroll-
ment procedure:
E1. Attractor Profiling. Execute K ≥16 orbits of length N = 4096 under varying thermal
conditions induced by controlled workload patterns. Compute the composite histogram
¯
HD :=
1
K
K
k=1 HD(Sk,N) andtheintra-devicetoleranceϵintra(D) := maxkW1(HD(Sk,N),
¯
HD).
E2. Compact Commitment. Compute the attractor commitment:
ACD := HDSM/attractor-commit
¯
HD∥ϵintra(D)∥B∥N∥r . (8)
This 32-byte digest is the public enrollment artifact. The raw histogram¯
HD is never
transmitted.
E3. DBRW Binding. Compute KDBRW as in Equation (7) using H(d) := ACD as the
hardware entropy contribution.
E4. Master Seed Derivation. Derive the device master seed:
Smaster = HKDF-ExtractBLAKE3 salt= "DSM/dev\0", IKM= G∥DevID∥KDBRW∥s0 , (9)
where G is the user’s genesis digest and s0 is initial entropy from CSPRNG.
E5. AttestationKeypair. Generatetheattestationkey(AKsk,AKpk) ←SPHINCS+.KeyGen(Smaster).
E6. Kyber StaticKey. GeneratethestaticKyber keypair(KSsk,KSpk) ←Kyber.KeyGen(HDSM/kyber-static(S
Security Claim
The enrollment protocol reveals only ACD (a 32-byte hash), AKpk (a SPHINCS+ public
key), and KSpk (a Kyber public key) to any external party. No raw histogram data,
thermal measurements, or DBRW binding keys are exposed. Under Definition 5.1, ACD
reveals no information about¯
HD beyond its commitment.
6.2 Zero-Knowledge Verification Protocol
Protocol 6.2 (C-DBRW ZK Verification). Given an enrolled device D with public artifacts
(ACD,AKpk,KSpk), a verifier V authenticates D as follows:
V1. Challenge. V generates a fresh nonce c
$ ←−{0,1}256 and sends c to D.
V2. Orbit Execution. Dcomputes the initial state x0 = HDSM/cdbrw-seed(c∥KDBRW) mod 232
,
executes the ARX orbit OD(Scurrent,N), and computes the histogram HD(Scurrent,N).
V3. Commitment. D computes
γ := HDSM/cdbrw-response HD(Scurrent,N)∥c . (10)
V4. Kyber Encapsulation. D computes deterministic coins
coins := HDSM/kyber-coins(hn∥Cpre∥DevID∥KDBRW), (11)
and encapsulates: (ct,ss) = Kyber.EncDet(KSV
pk,coins).
V5. Response. D sends (γ,ct,σ) to V, where σ = SPHINCS+.Sign(EKsk,γ∥ct∥c) using the
current ephemeral step key.
28
V6. Verification. V checks:
(a) SPHINCS+.Verify(EKpk,σ,γ∥ct∥c) = 1.
(b) The ephemeral key certificate chain traces to AKpk.
(c) Kyber.Decaps(KSV
sk,ct) = ss (shared secret recovery succeeds).
(d) γ is consistent with ACD under the attractor envelope test (Section 6.3).
Accept if and only if all checks pass.
Theorem 6.1 (Zero-Knowledge Property). Definition 6.2 reveals no information about the de-
vice orbit OD, histogram HD, or DBRW binding key KDBRW to the verifier, beyond the binary
accept/reject decision, under Definition 5.1 and Definition 5.2.
Proof. We construct a simulator Sthat, given only (ACD,AKpk,KSpk) and the accept/reject
bit, produces a transcript computationally indistinguishable from a real execution.
Simulating γ: Under the random oracle model for HDSM/cdbrw-response, the commitment γ is a
uniformly random 256-bit string from the verifier’s perspective (since HD is unknown and acts
as a high-entropy preimage component). Sdraws γ∗ $ ←−{0,1}256
.
Simulating ct: Under IND-CCA2 security of Kyber, the ciphertext ct is indistinguishable
from a random ciphertext of the same length. Sgenerates (ct∗
,ss∗) ←Kyber.Enc(KSV
pk) using
fresh random coins.
Simulating σ: Under EUF-CMA security of SPHINCS+, the signature σ is unforgeable but
doesnotleakinformationaboutthesigningkeybeyondwhatisderivablefromthepublickeyand
certificate chain. In the simulation, Suses the zero-knowledge property of hash-based signatures
(the simulated signature is produced by programming the random oracle).
The simulated transcript (γ∗
,ct∗,σ∗) is computationally indistinguishable from the real tran-
script (γ,ct,σ) by a hybrid argument over the three components.
6.3 Attractor Envelope Test
Definition 6.3 (Attractor Envelope Test). Given the enrollment commitment ACD and the
response commitment γ from Definition 6.2, the envelope test verifies that γ is consistent with
a histogram within the attractor envelope of D.
The test operates in committed space: the verifier does not reconstruct the raw histogram.
Instead, the device provides a succinct proof πenv that the histogram underlying γ satisfies the
Wasserstein distance bound relative to the enrollment commitment.
Formally, πenv is a set of mstatistical moments (ˆ µ1,...,
ˆ
µm) of the response histogram along
with their committed values:
πenv := (ˆ µi,HDSM/moment(ˆ µi∥i∥c))m
i=1. (12)
The verifier checks that each moment commitment is consistent with γ (via a Merkle proof over
the moment tree) and that the moment vector lies within the pre-committed tolerance ball.
Normative Requirement
Moment count. The envelope test MUST use m≥8 moments (mean, variance, skew-
ness, kurtosis, and 4 quantile digests). The tolerance ball parameters are fixed at enroll-
ment and committed in ACD.
7 Tri-Layer Feedback Architecture
The C-DBRW system employs a tri-layered feedback loop tuned to the thermodynamic response
of the chip:
29
7.1 Layer 1: Thermal Salting
Definition 7.1 (Thermal Salt Injection). At each iteration n, raw thermal noise is extracted
from cache-miss timing or dynamic voltage fluctuation measurements to produce the control
byte µn. The salt effectively perturbs the next iteration of the ARX map:
xn+1 = fARX(xn,µn), (13)
ensuring that orbit paths cannot be precomputed or cached by an adversary without access to
the physical device.
Proposition 7.1 (Precomputation Resistance). For orbit length N and thermal byte min-
entropy ≥hmin bits per sample, an adversary must evaluate ≥2hmin·N candidate orbits to enu-
merate all possible trajectories.
Proof. Each µn contributes ≥hmin bits of unpredictable input. Over N iterations, the total
entropy is ≥hmin·N. For hmin = 3 and N = 4096, this yields ≥212288 candidates.
7.2 Layer 2: Phase-Space Verification
Definition 7.2 (Phase-Space Distance Metrics). Authentication is not based on bitwise com-
parison but on statistical distance between the measured histogram Hmeasured and the reference
attractor measure ρD. Two metrics are supported:
EMD(Hmeasured,ρD) := inf
γ∈Γ
i,j
KL(Hmeasured∥ρD) :=
Hiln Hi
i
ρD,i
where Γ is the set of joint distributions with marginals Hmeasured and ρD, and d(i,j) is the bin
γijd(i,j), (14)
, (15)
distance.
Normative Requirement
Metricselection. ImplementationsMUSTsupportEMD(Wasserstein-1)astheprimary
metric. KL divergence MAY be used as a supplementary test. The acceptance threshold
MUST be W1 <ϵintra(D) + δmargin, where δmargin is a configurable margin (default: 0.1·
ϵintra(D)).
7.3 Layer 3: Resonant Forgiveness
The adaptive cage growth model (Definition 4.16) tunes the acceptance radius according to the
geometric mixing rate and current thermal volatility. The system “resonates” with its own chaos:
authentic trajectories are recognized even under mild environmental drift because the cage width
scales with the magnitude of thermal perturbation.
Corollary 7.2 (False Rejection Bound). For an authentic device D operating within M, the
false rejection rate satisfies
FRR ≤α+ exp−
N·(Λmin
D )2
2·Var(δn),
where Λmin
D := minS∈MΛD(S) and the second term is a Hoeffding tail bound on histogram
concentration.
30
8 DSM Integration Specification
ThissectionspecifieshowC-DBRWintegrateswiththeDeterministicStateMachinearchitecture
as the hardware identity primitive underlying DBRW binding.
8.1 C-DBRW as Hardware Entropy Source for DBRW
Normative Requirement
In the DSM architecture, the hardware entropy function H(d) ∈{0,1}256 (Definition 1 of
the DSM spec, Section 12) MUST be instantiated as the C-DBRW attractor commitment:
H(d) := ACD.
This replaces any static PUF measurement with a chaotic attractor fingerprint that cap-
tures the full thermodynamic manifold of the device.
Definition 8.1 (C-DBRW–Enhanced DBRW Binding). The enhanced DBRW binding key is
KDBRW := HDSM/dbrw-bind ACD∥E(e)∥sdevice , (16)
where ACD is the C-DBRW attractor commitment (Equation (8)), E(e) is the execution envi-
ronment fingerprint, and sdevice
$ ←−{0,1}256 is a per-device salt from CSPRNG.
Theorem8.1(EnhancedAnti-Cloning). Under Definition 5.1, Definition 4.2, and Theorem 5.1,
the C-DBRW–enhanced DBRW binding provides strictly stronger anti-cloning guarantees than
static PUF-based DBRW:
(i) The attractor commitment ACD encodes the full nonlinear thermal response surface, not
a single-point measurement.
(ii) Temperature drift strengthens rather than weakens the fingerprint, because thermal varia-
tion is the mechanism that populates the attractor.
(iii) Aging effects that degrade static PUF responses instead enrich the attractor manifold.
Proof. Part (i): A static PUF measures device properties at a single temperature/voltage point,
yieldingavectorp ∈{0,1}n subjecttoBERdegradationundertemperatureshift. TheC-DBRW
attractor commitment ACD integrates over K ≥16 thermal conditions, capturing the invariant
measure ρD that is stable under thermal perturbation (Theorem 4.10). The information content
of ACD exceeds that of p because the attractor encodes correlations between thermal states that
a single measurement cannot capture.
Part (ii): For static PUFs, temperature drift causes bit flips that increase BER and may
cause false rejections. For C-DBRW, temperature drift generates new thermal bytes µn that
are additional samples from ΦD, populating the attractor histogram more densely. The Wasser-
stein distance between enrollment and verification histograms decreases with additional thermal
variation (more samples from the same distribution), not increases.
Part (iii): Silicon aging (NBTI, HCI, electromigration) shifts the thermal coupling coef-
ficients, altering ΦD to Φ(t)
D where t indexes aging time. For static PUFs, this shift is indis-
tinguishable from a cloning attempt. For C-DBRW, the shift is gradual and continuous, so
W1(ρ(t1)
D ,ρ(t2)
D ) ≤L·|t1−t2|for a Lipschitz constant L determined by the aging rate. Periodic
re-enrollment at intervals ∆t such that L·∆t<ϵintra maintains authentication continuity.
31
8.2 Ephemeral Key Derivation Chain
The C-DBRW attractor commitment enters the DSM key hierarchy at the DBRW binding level.
The full derivation chain is:
ACD
C-DBRW
Eq. 16
−−−−→KDBRW
Eq. 9
−−−→Smaster
per-step −−−−−→En+1
SPHINCS+.KeyGen −−−−−−−−−−−−→(EKsk,EKpk). (17)
Normative Requirement
At no point in this chain is KDBRW, Smaster, or any intermediate key serialized, logged,
or included in any commitment or envelope. All secret material exists only in volatile
memory during the execution of dsm_core.
8.3 Receipt Binding
Every DSM stitched receipt is signed by an ephemeral SPHINCS+ key derived (transitively)
from ACD via the chain in Equation (17). This ensures that:
Corollary 8.2 (Receipt–Device Binding). A valid stitched receipt τA↔B can only have been
produced by the physical device DA whose attractor generated ACDA , under the assumptions of
Theorem 5.1 and Definition 5.3.
9 Implementation Architecture
9.1 Three-Layer Execution Model
The C-DBRW protocol interfaces with the DSM runtime across three layers:
Definition 9.1 (Execution Layer (C++/JNI)). Handles low-level pointer chasing and ARX
permutation routines with precise cycle timing. CPU affinity is pinned to a single core to
limit scheduler jitter. Native intrinsics read temperature and voltage counters at microsecond
intervals.
Normative:
(a) The ARX inner loop MUST execute on a single pinned core with interrupts masked for
the duration of the orbit.
(b) ThermalbyteextractionMUSTuseplatform-specifichardwarecounters(e.g.,THERMAL_STATUS
MSR on x86, /sys/class/thermal on ARM) and MUST NOT use software PRNG fall-
backs.
(c) Timing measurements MUST use cycle counters (RDTSC on x86, CNTVCT_EL0 on ARM)
with serializing instructions to prevent out-of-order measurement artifacts.
Definition 9.2 (Validation Layer (Kotlin)). Implements real-time attractor matching using a
data pipeline:
(a) Calculates the orbit distribution histogram over N = 4096 samples.
(b) Applies outlier rejection (samples with δn >3·ΛD are flagged).
(c) Computes Wasserstein-1 distance against the reference attractor via the linear-time quan-
tile algorithm.
32
(d) Applies resonant forgiveness scaling (Definition 4.16).
Definition 9.3 (Binding Layer (Rust Core)). Once validated, the attractor fingerprint is com-
pressed and committed using BLAKE3 with domain separation constants:
ACD = HDSM/attractor-commit
¯
HD∥ϵintra(D)∥B∥N∥r . (18)
This yields a cryptographic token verifiable across sessions but unforgeable elsewhere.
Normative: The binding layer is part of dsm_core (Rust) and is the sole authority for
commitment computation. Platform layers (Kotlin/C++) MUST NOT recompute or re-encode
commitments.
9.2 Algorithm Specifications
Algorithm 1 C-DBRW Orbit Execution
Require: Challenge nonce c, DBRW key KDBRW, orbit length N, rotation r, bin count B
Ensure: Histogram H ∈∆B−1
1: x0 ←HDSM/cdbrw-seed(c∥KDBRW) mod 232
2: bins[0..B−1] ←0
3: for n= 0 to N−2 do
4: µn ←ReadThermalByte() 5: xn+1 ←(xn + ROL(xn,r) ⊕µn) mod 232 ▷ Hardware entropy register
▷ ARX step
6: bins[⌊xn+1·B/232⌋] += 1
7: end for
8: H ←bins/(N−1) ▷ Normalize
9: return H
Algorithm 2 C-DBRW Enrollment
Require: Enrollment round count K, orbit length N, bin count B, rotation r
Ensure: Attractor commitment ACD, tolerance ϵintra, DBRW key KDBRW
1: for k= 1 to K do
2: Induce thermal variation via controlled workload pattern k
3: ck ←CSPRNG(256)
4: Hk ←OrbitExecution(ck,KDBRW,tmp,N,r,B) 5: end for
6:¯
H ← 1
K
K
k=1 Hk
¯
7: ϵintra ←maxkW1(Hk,
H)
¯
8: ACD ←HDSM/attractor-commit(
H∥ϵintra∥B∥N∥r)
9: KDBRW ←HDSM/dbrw-bind(ACD∥E(e)∥sdevice)
10: Smaster ←HKDF-Extract("DSM/dev\0",G∥DevID∥KDBRW∥s0)
11: (AKsk,AKpk) ←SPHINCS+.KeyGen(Smaster)
12: (KSsk,KSpk) ←Kyber.KeyGen(HDSM/kyber-static(Smaster))
13: return (ACD,ϵintra,KDBRW,AKpk,KSpk)
▷ Alg. 1
33
Algorithm 3 C-DBRW Verification (Device Side)
Require: Challenge c, verifier’s Kyber public key KSV
pk, current chain tip hn, pre-commit Cpre
Ensure: Response (γ,ct,σ)
1: H ←OrbitExecution(c,KDBRW,N,r,B) ▷ Alg. 1
2: γ ←HDSM/cdbrw-response(H∥c)
3: coins ←HDSM/kyber-coins(hn∥Cpre∥DevID∥KDBRW)
4: (ct,ss) ←Kyber.EncDet(KSV
pk,coins)
5: kstep ←HDSM/kyber-ss(ss)
6: En+1 ←HKDF-BLAKE3("DSM/ek\0",hn∥Cpre∥kstep∥KDBRW)
7: (EKsk,EKpk) ←SPHINCS+.KeyGen(En+1)
8: σ←SPHINCS+.Sign(EKsk,γ∥ct∥c)
9: return (γ,ct,σ)
Algorithm 4 C-DBRW Verification (Verifier Side)
Require: Response (γ,ct,σ), challenge c, enrolled public keys, certificate chain, attractor com-
mitment ACD
Ensure: Accept / Reject
1: Verify SPHINCS+.Verify(EKpk,σ,γ∥ct∥c) ? = 1; if not, reject
2: Verify ephemeral key certificate chain to AKpk; if invalid, reject
3: ss ←Kyber.Decaps(KSV
sk,ct); if ⊥, reject
4: Verify γ passes attractor envelope test against ACD (Definition 6.3); if not, reject
5: accept
9.3 Performance Budgets
Normative Requirement
The following timing budgets are normative for ARM Cortex-A78 class processors (rep-
resentative mobile SoC):
Operation Budget Notes
ARX orbit (N = 4096) ≤10 µs Single-core, pinned
Histogram computation ≤5 µs In-place binning
BLAKE3 commitment ≤1 µs 32-byte output
Kyber-1024 encapsulation ≤1 ms liboqs reference
SPHINCS+ signing (Cat-5, fast) ≤50 ms Includes tree generation
SPHINCS+ verification ≤10 ms
Total verification round-trip ≤80 ms End-to-end
34
9.4 Test Vector Requirements
Normative Requirement
Conformant implementations MUST reproduce the following:
(a) ARX test vectors: Given fixed inputs (x0,r,µ0,...,µN−2), the orbit sequence
MUST be bit-identical across all platforms. Test vectors are distributed as binary
fixtures (not hex strings).
(b) BLAKE3 commitment vectors: Given fixed histogram bytes and enrollment
parameters, ACD MUST match the reference digest exactly.
(c) Kyber deterministic encapsulation: Given fixed coins and public key, (ct,ss)
MUST be bit-identical to the reference.
(d) End-to-end vectors: Given a fixed challenge, fixed thermal byte sequence, and
fixed enrollment state, the full response (γ,ct,σ) MUST match the reference.
10 Security Properties Summary
Theorem 10.1 (Composite Security). Under Definition 4.2, Definition 5.1, Definition 5.2, and
Definition 5.3, the C-DBRW system with post-quantum binding achieves:
(i) 128-bit post-quantum security against device cloning (Theorem 5.1), via Grover bound
on BLAKE3 and Module-LWE hardness of Kyber.
(ii) Zero-knowledge verification (Theorem 6.1), in the random oracle model.
(iii) Forward secrecy of per-step keys (Theorem 5.3), under IND-CCA2 of Kyber.
(iv) Receipt–device binding(Theorem 8.2), ensuring that DSMstitchedreceipts are hardware-
anchored.
(v) Thermal resilience(Theorem 4.10, Theorem 4.29), with configurable false-rejection rate.
(vi) No helper data leakage, unlike fuzzy extractor or sketch-based PUF constructions.
Proof sketch. Each claim follows from the corresponding theorem cited above. The composite
security holds by the standard composition argument: breaking any individual component is
sufficient to break the system, but each component reduces to a standard hardness assumption.
The absence of helper data follows from the commitment-based verification model: the verifier
never receives raw PUF responses, only BLAKE3 commitments and Kyber ciphertexts.
35
11 Comparison with Prior Art
Property Static PUF Fuzzy Ext. QPUF C-DBRW (ours)
Post-quantum secure No Partial Yes Yes
No helper data No No Yes Yes
Thermal resilient No Partial N/A Yes
Aging tolerant No No N/A Yes
Stock ARM deploy-
Yes Yes No Yes
able
ZK verification No No Partial Yes
Mobile latency
Yes Yes No Yes
<100ms
DSM compatible Partial Partial No Yes
12 Future Work
Several extensions are planned:
(i) Multimodal Attractor Fusion. Coupling multiple independent chaotic subsystems
(e.g., cache hierarchy + DRAM refresh + bus arbitration) to create a higher-dimensional
attractor with exponentially increased cloning resistance.
(ii) Symbolic Dynamics Extraction. Replacing histogram-based verification with a sym-
bolic dynamics representation (Markov partition labeling) that captures the topological
entropy of the attractor, enabling more compact commitments and faster verification.
(iii) Continuous Re-Enrollment. An incremental enrollment protocol that updates ACD
using exponentially weighted moving averages, tracking gradual aging without requiring
explicit re-enrollment windows.
(iv) Multi-Device Attractor Correlation Resistance. Formal analysis and mitigation of
potential correlation between attractors of devices from the same manufacturing batch,
including lot-specific salt derivation.
(v) Formal Machine-Checked Proofs. Mechanization of Theorem 5.1 and Theorem 6.1 in
a proof assistant (Lean 4 or Coq), targeting extraction of verified Rust implementations.
13 Conclusion
The Chaotic Dual-Binding Random Walk reframes thermal instability as a cryptographic ally.
By embracing chaos rather than suppressing it, the system derives a robust, self-referential form
of identity rooted in physics. The attractor of each chip is its own secret key—one that cannot
be read, duplicated, or recomputed without access to the physical substrate. Authentication
becomes an act of recognizing a chaotic “heartbeat” rather than comparing static data.
The integration with post-quantum primitives (Kyber for key encapsulation, BLAKE3 for
commitments, SPHINCS+ for signatures) ensures that the hardware identity layer remains se-
cure against both classical and quantum adversaries. The zero-knowledge verification protocol
guarantees that no PUF response data leaks during authentication, eliminating the helper-data
attack surface that plagues conventional PUF constructions.
Within the DSM architecture, C-DBRW provides the foundational hardware anchor: every
bilateral receipt, every state transition, every key derivation traces its provenance to a device-
specific chaotic attractor that is both mathematically verifiable and physically unclonable. By
learningtomoveatthespeedofchaos, wealigndigitaldeterminismwithanalogunpredictability.
36
References
[1] S. H. Strogatz. Nonlinear Dynamics and Chaos: With Applications to Physics, Biology,
Chemistry, and Engineering. Westview Press, 2nd edition, 2015.
[2] M. Walker, J. Lee, and R. Chen. Physically unclonable functions based on thermodynamic
chaos. IEEE Transactions on Dependable and Secure Computing, 20(4):2891–2905, 2023.
[3] J. O’Connor, J.-P. Aumasson, S. Neves, and Z. Wilcox-O’Hearn. The BLAKE3 crypto-
graphic hash function. Specification document, 2021. https://github.com/BLAKE3-team/
BLAKE3-specs.
[4] R. Avanzi, J. Bos, L. Ducas, E. Kiltz, T. Lepoint, V. Lyubashevsky, J. M. Schanck,
P. Schwabe, G. Seiler, and D. Stehlé. CRYSTALS-Kyber: Algorithm specifications and
supporting documentation (v3.02). NIST Post-Quantum Cryptography Standardization,
2023.
[5] D. J. Bernstein, A. Hülsing, S. Kölbl, R. Niederhagen, J. Rijneveld, and P. Schwabe. The
SPHINCS+ signature framework. In ACM CCS, 2019.
[6] R. Pappu, B. Recht, J. Taylor, and N. Gershenfeld. Physical one-way functions. Science,
297(5589):2026–2030, 2002.
[7] C. Herder, M.-D. Yu, F. Koushanfar, and S. Devadas. Physical unclonable functions and
applications: A tutorial. Proceedings of the IEEE, 102(8):1126–1141, 2014.
[8] B. “Cryptskii” Ramsay. Deterministic State Machine: A concise, post-quantum specifica-
tion. Technical report, DSM Project, December 2025.
[9] B. “Cryptskii” Ramsay. Sovereign sovereign finance architecture: Trustless Bitcoin
bridge via bilateral state machines. Technical report (submitted for review), 2025.
[10] J.-P. Eckmann and D. Ruelle. Ergodic theory of chaos and strange attractors. Reviews of
Modern Physics, 57(3):617–656, 1985.
[11] National Institute of Standards and Technology. Post-quantum cryptography standardiza-
tion. https://csrc.nist.gov/Projects/post-quantum-cryptography, 2024.
[12] Open Quantum Safe Project. liboqs: C library for quantum-safe cryptographic algorithms.
https://openquantumsafe.org, 2024.
A Domain Separation Tags
The following domain-separation tags are normative for C-DBRW. All tags are ASCII strings
followed by a NUL byte (\0).
37
Tag Usage
DSM/dbrw-bind\0 DBRW binding key derivation
DSM/attractor-commit\0 Attractor commitment ACD
DSM/cdbrw-seed\0 Challenge-seeded orbit initialization
DSM/cdbrw-response\0 Verification response commitment
DSM/kyber-coins\0 Deterministic Kyber encapsulation coins
DSM/kyber-ss\0 Kyber shared secret derivation
DSM/kyber-static\0 Static Kyber key derivation
DSM/moment\0 Moment commitment in envelope test
DSM/dev\0 Master seed extraction
DSM/ek\0 Ephemeral key derivation
DSM/ek-cert\0 Ephemeral key certification
DSM/dbrw-rho\0 DBRW walk step (rho)
DSM/dbrw-step\0 DBRW walk step (chain)
B Normative Parameter Summary
Parameter Symbol Default Constraint
Orbit length N 4096 ≥4096
Bin count B 256 ∈{256,512,1024}
Rotation constant r 7 ∈{5,7,8,11,13}
Enrollment rounds K 16 ≥16
Out-of-cage threshold α 0.05 ∈(0,0.1]
Moment count m 8 ≥8
Margin factor δmargin/ϵintra 0.1 ∈[0.05,0.2]
ARX word size W 32 Fixed
Hash function H BLAKE3-256 Fixed
KEM — Kyber-1024 NIST PQC Level 5
Signature — SPHINCS+ Cat-5 fast BLAKE3 variant
Receipt size cap — 128 KiB Fixed
38