# DSM TLA+ model (abstracted)

This folder contains an **abstract** TLA+ specification of some DSM mechanics.
It is intended to check **control-flow/symmetry/ownership** style invariants, not to
prove the full cryptographic or proof-carrying protocol.

The TLA+ specs do **not** execute the Rust implementation directly. The bridge
to real code lives in `tools/vertical_validation`:

- `cargo run -p dsm_vertical_validation -- tla-check` runs the bounded TLC suite.
- `cargo run -p dsm_vertical_validation -- tla-check --include-liveness` adds the
  extended bounded profile plus the standalone bilateral liveness spec. This is
  opt-in and is intentionally **not** part of the fast CI path.
- `cargo run -p dsm_vertical_validation -- property-tests ...` runs randomized
  checks against the real `StateMachine`.
- `cargo run -p dsm_vertical_validation -- implementation-traces` runs fixed,
  deterministic traces through the real `StateMachine`, `BilateralTransactionManager`,
  `TokenStateManager`, and receipt verifier.
- `cargo run -p dsm_vertical_validation -- tla-check` also links the focused
  standard TLA specs to matching real-code traces, and now also replays a
  deterministic TLC-produced simulation trace into Rust 1:1, so the same report
  shows TLC, literal trace replay, and linked real-code enforcement together.
- CI runs all three so the abstract model and the direct-code checks stay
  enforced together.

Today the integration links `DSM.tla` configs and `DSM_Tripwire.tla` to
implementation-backed traces covering state-machine execution, bilateral
precommit/finalize behavior, DJTE emission verification, DLV manager state,
token conservation, and receipt-level Tripwire enforcement. The same `tla-check`
command also generates deterministic TLC simulation traces and replays their
exact state paths inside Rust shadow models of `DSM.tla` and `DSM_Tripwire.tla`.
The standalone liveness spec is available via `--include-liveness`, but it is
kept out of the default suite to avoid slowing down the standard regression gate.

## Verification boundary

- `tla/` is a **bounded finite-state** verification layer. It is excellent for
  catching bookkeeping, refinement, and interleaving bugs, but it is not an
  unbounded proof of the full protocol.
- The stronger local invariants in `DSM.tla` act like inductive proof
  obligations over the current abstraction. They tighten what bounded TLC must
  preserve, but they remain bounded checks.
- Post-quantum security assumptions stay **outside** the TLA abstraction.
  SPHINCS+, ML-KEM, and Shor-related rationale are documented in the security
  and cryptography books; the TLA specs assume those external guarantees hold.
- Apalache is a future follow-up, not part of the current toolchain. The models
  would need additional reshaping before symbolic checking is worth adopting.

## What this model *does* cover

- Device membership under a genesis (`devices`), with no-duplicate-device invariant.
- Symmetric bilateral relationship activation + a monotonically increasing `tip`.
- Online message queuing (`pendingMsgs`) and processing.
- A simple key-generation gate (`keys`) used as a precondition for “sign/encrypt”.
- Offline session symmetry (`offlineSessions`) + a transfer step that increments tips.
- DLV ownership (`vaults` + `vaultState.owner`) and a trivial unlock predicate.
- Storage node membership (`storageNodes`) with stub store/replicate actions.
- DJTE counters (`activatedDevices`, `emissionIndex`, `shardTree`) in **placeholder** form.

## What this model *does NOT* cover

- Canonical protobuf encodings, Base32, b0x addressing, replica placement.
- SPHINCS+/Kyber algorithms, signature validation, proof objects, HKDF/DBRW.
- Explicit quantum attack simulation or Shor-style crypto-break modeling.
- Per-device SMT replace semantics, tripwire consumption tracking.
  (See `DSM_Tripwire.tla` for a focused model of these invariants).
- DJTE proof-carrying winner selection, shard descent proofs, spent-proof SMT.
	Winner selection in this model is deterministic and seed-based (k-th-min with
	k = seed % |activatedDevices|). It is NOT proof-carrying and NOT exact-uniform;
	modulo selection can introduce bias unless additional assumptions are modeled.

If you need those, the model should be refined by introducing explicit structures
(e.g., SMT/accumulator trees) and by replacing nondeterministic `CHOOSE` with
modeled deterministic selection.

## New Modules

### DSM_Tripwire.tla
A focused specification modeling the **Atomic Interlock Tripwire** and **Causal Consistency**
without wall clocks. It specifically verifies that linear device histories + SMT check
prevent fork acceptance even in the presence of an active adversary attempting
replay/fork strategies. This is the bilateral-tip SPECIAL CASE of the general
guarded kernel below: its uniqueness key is the concrete pair `(rel, oldTip)`.

### DSM_OfflineAnchorSingleAppliance.tla
The **offline-anchor SPECIAL CASE** of the same guarded kernel, exactly parallel
to `DSM_Tripwire.tla`'s bilateral case. It models ONE correct enrolled
offline-bearer appliance (v2 "Software Authority, Hardware Identity", July 2026)
through its full `Prepare → Commit → Emit → Finalize` cycle plus `Recover` and
`PowerLoss`, and proves DIRECTLY that a single appliance cannot originate two
valid releases from one SMT anchor origin `(R_i, h_i, u_i)`. Not "they collide
later", not "detected on reconciliation" — the second release cannot be
constructed inside the appliance state machine. The kernel's abstract resource
key is instantiated by the anchor origin: parent `R_i` (device SMT root),
descriptor `(h_i, u_i)` (offline frontier + committed SMT anchor counter).
Uniqueness is a SOFTWARE property of the SMT counter leaf and the
single-prepared-record / atomic-counter-advance discipline; the physical
TROPIC01 counter `H` is a non-rewind floor synchronized one-to-one to `u`
(`u = H0 - H`), never an acceptance authority. No fused anchor head, no boot
ticket, no receiver-witnessed counter read (all removed by the correction).

The two adversary actions `AttemptSecondPrepareSameOrigin` and
`AttemptSecondCommitSameOrigin` are deliberately included and TLC proves them
never enabled: the re-pin `o.u = H0 - physH` and the linearity guard
`RecOrigin ∉ consumedOrigins` are load-bearing (removing either falsifies
`NoTwoCommittedSameOrigin`). Six invariants hold — `NoTwoEmittedSameOrigin`,
`NoTwoCommittedSameOrigin`, `CounterSync`, `CommitAdvancesOrigin`,
`SecondSameOriginFails`, `RecoveryIdempotence` — over 123 distinct states.
The universal counterpart is `lean4/DSMOfflineAnchorOrigin.lean`
(`offline_anchor_origin_unique`, axiom-free), which ties the anchor origin to
the general theorem via `keyOf_inj`. This is the v2 replacement for the
boot-fenced offline model.

```zsh
cd tla
java -cp tla2tools.jar tlc2.TLC -config DSM_OfflineAnchorSingleAppliance.cfg DSM_OfflineAnchorSingleAppliance.tla
```

### Guarded kernel: DSM_Guarded.tla and companions
Machine-checkable realization of the guarded linear constraint system paper
(Appendix B), with the general key-scoped statement over an abstract resource
consumption key and an arbitrary guard family. The Lean counterpart
(`lean4/DSMGuardedTripwire.lean`) proves the universal theorems; these modules
model-check concrete instances and, critically, demonstrate the property is
load bearing through deliberate falsification.

The kernel states fork exclusion at two distinct levels, and both are checked:

- **Static (per-state) form**, invariant `Safety`: no reachable state has two
  conflicting `Step_K`-enabled successors. This is the paper's Theorem 2/4 as
  literally written. It requires guard-family well formedness (G5/G7): a
  key-split family violates it at depth 0, before anything is realized.
- **Dynamic (trace) form**, invariant `RealizedHistoryUnique`: the ledger of
  accepted receipts never contains two receipts consuming the same
  `(parent, key)` with different successors. This is the form that matches
  `DSM_Tripwire.tla`'s ledger-style invariant, lifted to the abstract key.

Instances and expected TLC outcomes:

| Config | Module | Family | Expected |
|---|---|---|---|
| `DSM_GuardedMC_WF.cfg` | `DSM_GuardedMC_WF.tla` | well formed | No error (Safety + RealizedHistoryUnique) |
| `DSM_GuardedMC_Fork.cfg` | `DSM_GuardedMC_Fork.tla` | key split | `Invariant Safety is violated` at the initial state (static falsification) |
| `DSM_GuardedMC_Fork_Ledger.cfg` | `DSM_GuardedMC_Fork.tla` | key split | No error: a SINGLE honest verifier never realizes a local fork even under a malformed family (paper Prop 11) |
| `DSM_GuardedMC_BilateralWF.cfg` | `DSM_GuardedMC_BilateralWF.tla` | relationship scoped, attempted same-parent conflict included | No error: derived keys + one receiver per relationship make the fork unconstructible |
| `DSM_GuardedMC_BilateralFork.cfg` | `DSM_GuardedMC_BilateralFork.tla` | structure removed (free keys, two independent receivers of one parent) | `Invariant CrossVerifierAgreement is violated`: the contrast identifying the load-bearing structure |

`DSM_GuardedBilateral.tla` encodes the two structural facts that make
"two receivers, same parent" unconstructible in online DSM. First, every
counterparty relationship is its own straight hash chain and the derived
consumption key embeds the relationship identity, so a parent under one
relationship is not replayable under another even when chains reuse node
names (paper Sec 6, Def 27/33, Rule 2). Second, the topology is bilateral: a
relationship step has exactly one receiver, the counterparty of that
relationship, so each relationship is modeled with a single acceptance locus.
Online acceptance is the receiver's own frontier and proof checks (Def 55);
no co-signing round is part of the online path. The WF instance deliberately
includes an attempted same-parent conflict and TLC proves it cannot fork in
any interleaving. The Fork instance is the structure-removed contrast: free
keys and two independent receivers of one parent, neither of which exists in
online DSM, and only then does the cross-receiver fork appear. The one
setting where a spendable object is genuinely presented to multiple distinct
receivers is offline bearer mode, governed by the fused anchor, the Def 56
pending lock, the offline anchor design's co-signed precommit, and
reconciliation (paper Sec 29, Thm 14), modeled separately.

```zsh
cd tla
java -cp tla2tools.jar tlc2.TLC -config DSM_GuardedMC_WF.cfg            DSM_GuardedMC_WF.tla
java -cp tla2tools.jar tlc2.TLC -config DSM_GuardedMC_Fork.cfg          DSM_GuardedMC_Fork.tla
java -cp tla2tools.jar tlc2.TLC -config DSM_GuardedMC_Fork_Ledger.cfg   DSM_GuardedMC_Fork.tla
java -cp tla2tools.jar tlc2.TLC -config DSM_GuardedMC_BilateralWF.cfg   DSM_GuardedMC_BilateralWF.tla
java -cp tla2tools.jar tlc2.TLC -config DSM_GuardedMC_BilateralFork.cfg DSM_GuardedMC_BilateralFork.tla
```

Note on `*_TTrace_*` files: TLC writes trace-exploration specs whenever a run
reports a violation, so the two EXPECTED-violation configs above regenerate
them on every run. They are disposable artifacts. The older
`DSM_GuardedMC_Fork_TTrace_*.bin` files (June 30) came from the pre-merge
falsification harness on the `feat/formalize-dsm-guarded-tripwire` branch and
are superseded; they can be deleted.

### DSM_dBTC_TrustReduction.tla
A focused dBTC trust-boundary model. It makes the mainnet settlement predicate
explicit and checks that final burn is reachable only when Bitcoin-side evidence
includes SPV inclusion, PoW-valid headers, checkpoint-rooted continuity,
same-chain anchoring, and confirmation depth at or above `dmin`. A weakened
network profile is modeled separately to show that signet/testnet-style evidence
does **not** justify the same minimum-trust claim.

See also `tla/DBTC_RUST_CORRESPONDENCE.md` for the code-level mapping from the
formal predicates to the Rust verifier path.

## Running TLC

The config file `DSM.cfg` defines a larger exploratory model (may not terminate quickly).
A tiny, terminating model is provided as `DSM_tiny.cfg`.
A deeper bounded manual profile is provided as `DSM_extended.cfg`.

From the repo root:

```zsh
./tla/run_tlc.sh tla/DSM.tla tla/DSM_tiny.cfg

# Extended bounded profile (manual / opt-in)
./tla/run_tlc.sh tla/DSM.tla tla/DSM_extended.cfg

# Exploratory (larger state space; consider adding timeout)
./tla/run_tlc.sh tla/DSM.tla tla/DSM.cfg

# Standalone bilateral liveness model
./tla/run_tlc.sh tla/DSM_BilateralLiveness.tla tla/DSM_BilateralLiveness.cfg
```

Or via the integrated Rust wrapper:

```zsh
cargo run -p dsm_vertical_validation -- tla-check
cargo run -p dsm_vertical_validation -- tla-check --include-liveness
cargo run -p dsm_vertical_validation -- property-tests --iterations 5 --seed 42
cargo run -p dsm_vertical_validation -- implementation-traces
```

Tip: if the state space is large, shrink constants in `DSM.cfg` (fewer devices, smaller payloads).
