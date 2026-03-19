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
replay/fork strategies.

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
