# DSM — Deterministic State Machine

[![codecov](https://codecov.io/gh/deterministicstatemachine/dsm/graph/badge.svg?branch=main)](https://app.codecov.io/gh/deterministicstatemachine/dsm)

DSM is a state and identity layer in which every participant verifies state transitions directly, at the edge, with no global consensus, no validator ordering, no sequencer, and no wall clock. State lives in relationship-local hash chains anchored in a per-device sparse Merkle tree. Identity is device-bound and mnemonic-rooted. Every hash is domain-separated BLAKE3 and every signature is SPHINCS+. A transition is accepted because it is hash-adjacent to the state it consumes and satisfies the committed rules, not because anyone voted on it.

DSM is not a blockchain, a rollup, or a payment-channel network. Storage nodes hold bytes and never decide anything. The three product surfaces built on the primitive are **Sovereign Finance (SoFi)**, an on-device AMM market with no counterparty and no operator; the **offline anchor appliance**, a hardware identity for offline bearer transfer built on an RP2350 and a TROPIC01 secure element; and **dBTC**, Bitcoin-backed DSM state whose withdrawal is a consumption of live DSM state rather than a custodian's decision.

This README is the map for release `v0.1.0-beta.4`. Every claim below carries one of five status tags: **proven on hardware** (exercised end to end on phones against the live fleet), **host-tested** (green in the Rust board), **silicon pending** (firmware written and wired, awaiting the named validation row), **fenced** (code present, refused by a named guard), or **core-only** (implemented in the core crate, not wired to a route).

## Beta testers — start here

**[⬇ Download the latest DSM Wallet APK](https://github.com/deterministicstatemachine/dsm/releases/latest)**

1. **Uninstall any previous beta.** Beta releases are clean cuts; there is no state migration between them.
2. Download the APK from the release page to your Android device.
3. Enable **Install from unknown sources** if prompted.
4. Open the file to install, then launch the DSM Wallet.

The release page for this cut is [v0.1.0-beta.4](https://github.com/deterministicstatemachine/dsm/releases/tag/v0.1.0-beta.4). CI publishes the storage-node binary, the frontend bundle, and the SBOM; the APK is signed and uploaded by the maintainer.

> **Early beta.** This release exists for developer onboarding and community feedback. It contains novel cryptographic protocols and is not ready for production use or for holding value. The app talks to a beta storage fleet on the `dsm-testnet` network id, and beta devices need an operator-side allowance before the fleet accepts their writes. If you want to test with real devices, open a [support](SUPPORT.md) thread first.

## Who this README is for

- **Wallet and beta tester:** the section above, then the [Android app](#android-app-and-frontend) section.
- **Protocol reader (SoFi, dBTC, identity):** [Protocol pillars](#protocol-pillars), [Sovereign Finance](#sovereign-finance-sofi), [dBTC](#dbtc--the-dbtc-is-the-asset-the-bitcoin-key-is-machinery).
- **Firmware and hardware:** [Offline anchor appliance](#offline-anchor-appliance--software-authority-hardware-identity) and `crates/`.
- **Contributor:** [Development workflow](#development-workflow), then [CONTRIBUTING.md](CONTRIBUTING.md).

## Status board

| Surface | Status | Evidence |
|---|---|---|
| Identity and genesis (mnemonic-rooted, self-attested, published to the fleet) | proven on hardware | 4 devices wiped and re-created against the live fleet 2026-09-13, each identity accepted by all 5 nodes |
| Bilateral transfers, offline cash load/unload | proven on hardware | two-device end-to-end 2026-08-24; byte-identical state on both sides |
| BLE command path (`ble.command`, protobuf-only) | host-tested | route registered in the SDK; dispatch to the Android BLE backend |
| SoFi: DLV markets, routing, routed unlock, reconcile, close, receipts | proven on hardware | full lifecycle on 4 phones 2026-09-13, see [Sovereign Finance](#sovereign-finance-sofi) |
| Token surface: create, mint, burn, adopt, policy; faucet | proven on hardware | same run; capped issuance stays fenced in beta |
| Storage fleet: 5 nodes, quorum 3 of 5, write-once registers | live | `BETA_ROOT_REGISTER_MEMBERS` pins the 5 members; `dsm_storage_node` serves them |
| Offline anchor appliance: core, verifier, SPHINCS+ | host-tested | `dsm-anchor-core`, `dsm-anchor-verifier`, `dsm-sphincs` are workspace members in the board |
| Offline anchor appliance: RP2350 firmware, TrustZone monitor | silicon pending | rows 0, 1a, 2a of the validation matrix PASS 2026-07-12; remaining rows pending a clean TROPIC power cycle |
| dBTC: origin admission, burn-gated withdrawal, successor vaults | fenced | design frozen as DSM-NATIVE dBTC V1; tap creation and partial exit refused by `DBTC_PUBLIC_WITNESS_FENCE` |
| Emissions (DJTE) | core-only | schedule and ticket selection in `dsm/src/emissions`; the faucet consumes tickets |
| Formal models: TLA+, Lean 4, vertical validation | host-tested | `formal-validation` and `lean` CI jobs; see [Formal verification](#formal-verification) |

## Workspace map

```
dsm/
├── dsm_client/deterministic_state_machine/
│   ├── dsm/            core: state machine, crypto, bilateral, dlv, economic, ccb, vault, emissions   (member)
│   └── dsm_sdk/        SDK and route handlers: identity, tokens, dlv.*, route.*, storage, faucet, bitcoin   (member)
├── dsm_storage_node/   index-only persistence over PostgreSQL; write-once registers; Terraform + deploy   (member, excluded from the Rust board)
├── dsm_client/android/ Kotlin container: WebView + JNI bridge, BLE, USB anchor transport
├── dsm_client/frontend/ React wallet UI, pure rendering over the Envelope v3 bridge
├── crates/
│   ├── dsm-anchor-core/          hardware-free appliance core: root-advance message, three-signature release, prepare/commit/emit/finalize   (member)
│   ├── dsm-anchor-verifier/      receiver-side relay primitives and the exact counter check, tropic01-free   (member)
│   ├── dsm-sphincs/              no_std BLAKE3-keyed SPHINCS+, byte-compatible with the core, shared with firmware   (member)
│   ├── dsm-anchor-pico/          RP2350 Pico 2 W firmware over libtropic-rs   (excluded: thumbv8m-only)
│   ├── dsm-anchor-secure-monitor/ TrustZone-M Secure world: TROPIC01, partition key, counter, seal, the single NSC gateway   (excluded: thumbv8m-only)
│   ├── dsm-anchor-nonsecure-app/ TrustZone-M Non-secure world: USB-CDC, protobuf, transport   (excluded: thumbv8m-only)
│   ├── dsm-anchor-hw-verifier/   the real libtropic session driver   (excluded: needs the sibling libtropic-rs checkout)
│   ├── dsm-anchor-bench/         used-chip bench harness, non-mutating proofs only   (excluded: native serial dependency)
│   └── dsm-android-anchor/       on-device glue that installs the USB appliance into the SDK bridge   (excluded: built only by cargo-ndk)
├── tools/vertical_validation/    implementation traces, adversarial runs, KATs, formal report
├── tla/                TLA+ specs and TLC configs
├── lean4/              Lean 4 proofs
├── proto/              dsm_app.proto, the only wire format
├── ci/ scripts/ Makefile   gates, deploy helpers, the maintained entry points
└── docs/               handbook, papers and amendments, ADRs, audits, reports, anchor TrustZone docs
```

Membership is declared in the root [Cargo.toml](Cargo.toml). The default workspace is tropic01-free by construction; the excluded crates are built from their own directories or by the Android pipeline.

## Protocol pillars

- **Hash-adjacent bilateral state.** Each relationship is its own chain; a transition consumes its identified parent, and conflicting successors to one consumed state are excluded by the Tripwire. There is no global ordering to wait for. Handbook: [Protocol Reference](docs/book/05-protocol-reference.md).
- **Device state and the SMT.** A device's head commits every relationship tip, its balance projections, and adoption leaves into one sparse Merkle tree. The per-device leaf cache is bounded (1024 leaves, FIFO eviction), which is a stated property, not a hidden one.
- **Canonical commit bytes (CCB).** Everything that is hashed or signed is a domain-separated canonical encoding produced by the core; protobuf bytes are transport and are never signed. Registry: [ccb-object-registry.md](docs/papers/ccb-object-registry.md).
- **Economic root register.** Admitted economic state is rooted in a register kept on the storage fleet as write-once slots, pinned to a member set and a quorum. Storage nodes accept or refuse a write; they never interpret it ([ADR 0002](docs/adr/0002-storage-acceptance-is-not-cryptographic-endorsement.md)).
- **Genesis v3, mnemonic-rooted.** Genesis is derived from the BIP39 mnemonic and self-attested on the device (`createGenesisV2`), then the identity record is published to the fleet and accepted at quorum. There is no MPC service and no genesis server.
- **Determinism bans.** No wall-clock markers in protocol or core logic. No JSON in protocol paths; Envelope v3 protobuf only, strict-fail on any other version. Hex is banned; Base32 Crockford is the only string form and only at UI, QR, and log boundaries. No `unsafe` in core protocol paths without review. Full list: [Hard Invariants](docs/book/appendix-b-hard-invariants.md).
- **Post-quantum by default.** BLAKE3 everywhere, always with a domain tag; SPHINCS+ (BLAKE3-keyed, byte-compatible with `dsm-sphincs`) for every signature. Handbook: [Cryptographic Architecture](docs/book/06-cryptographic-architecture.md).

## Sovereign Finance (SoFi)

SoFi is an AMM market that runs on the participants' own devices. A liquidity provider owns a **DLV** (a deterministic liquidity vault): a constant-product pool over two adopted tokens, created from the owner's own balances, anchored in the owner's SMT, and advertised to the storage fleet. A trader finds the vault, binds a route, and settles a swap against it with evidence that both sides and any later verifier can check. There is no order book, no operator, and no pool contract; the vault is the owner's state, and the swap is a bilateral transition with a settlement bundle attached.

**Lifecycle, by route name.**

1. `token.create` registers a token under a policy and adopts it for the creator; creation charges a fee in ERA (the builtin asset), read from `tokens.getFeeSchedule`. `token.mint` credits supply under an authorized-issuance operation (op `0x0029`); `token.burn` and `token.forget` are the inverses. `token.adoptionQr` and `tokens.addByAnchor` let another device adopt the token, which commits an `AdoptToken` advance on that device.
2. `faucet.claim` credits 100 ERA to a fresh device from the beta emission schedule so it can pay fees.
3. `dlv.create` funds the vault. The reserves leave the owner's projected balances at commit; the owner's wallet shows the debit immediately.
4. `route.publishRoutingAdvertisement` publishes the pair, reserves, and fee to the fleet; `dlv.listOwnedAmmVaults` lists what this device runs.
5. A trader calls `route.syncVaultsForPair`, `route.listAdvertisementsForPair`, and `route.findAndBindBestPath` to bind a path and a quote.
6. `route.signRouteCommit` signs the route. The final hop's output token must already be adopted on the signing device. If it is not, the route is refused locally and nothing is committed or published for it: no external commitment, no vault-pending pointer, no storage write. **Adoption precedes receipt** is the rule the whole surface follows.
7. `route.publishExternalCommitment` publishes the trader's commitment to the fleet; `route.computeExternalCommitment` and `route.isExternalCommitmentVisible` let either side check it.
8. `dlv.unlockRouted` executes the swap against the vault. It applies the adoption gate again and binds the unlocker's key, so a device that has not adopted the output asset is refused here even if it somehow holds a route.
9. `dlv.reconcile` lets the owner catch up on every settled swap in order, materializing the new reserves and a fresh owner baseline. `storage.sync` runs the same engine.
10. `dlv.close`, `dlv.claim`, `dlv.invalidate`, `dlv.composeVault`, and `dlv.lineageQuarantine` are the terminal and containment paths: close derives every close fact from the composed history; quarantine contains a lineage after a temporal trigger without clearing it.

**Evidence objects.** A swap produces a settlement bundle (Definition 6.14), a receipt (Definition 14.2, never gating release), a quorum bind that ties the settlement to the fleet's write-once settlement slot, and a trader fence that prevents a second settlement against the same slot. All of these are canonical commit bytes; all are foreign-verifiable from the bundle alone.

**Proven on hardware, 2026-09-13.** On a wiped five-node fleet with four phones: each device created its identity (accepted 5 of 5) and claimed the faucet; the owner created a token, minted supply, and funded a vault at 30 bps; two traders adopted the token and swapped, each landing the expected output; a third device that had never adopted the token was refused at `dlv.unlockRouted`; the owner reconciled through three vault generations; a second swap by the first trader settled against the reconciled reserves; the owner's wallet showed the vault's reserves debited from the start.

Read next: [SoFi LP walkthrough](docs/sofi-lp-walkthrough.md), [two-device playbook](docs/sofi-two-device-playbook.md), [cross-device test](docs/cross-device-sofi-test.md), the SoFi specification in [sofispecs.instructions.md](.github/instructions/sofispecs.instructions.md), and the frozen amendments in [docs/papers/](docs/papers/) (`amendment-2c-*.md`).

## dBTC — the dBTC is the asset; the Bitcoin key is machinery

dBTC is Bitcoin-backed economic state native to DSM (specification: *DSM-NATIVE dBTC V1*; reader's guide: *The dBTC Is the Asset; the Bitcoin Key Is Machinery*). A real Bitcoin output is funded under a vault profile and verified at the required depth; exactly that quantity is admitted as dBTC into DSM state. From then on dBTC moves the way every other DSM asset moves: as ordinary bilateral transitions, online or offline, with no Bitcoin transaction, no confirmation, no depositor, no custodian, and no ledger.

**The one rule everything follows from:** holding Bitcoin-related bytes is not holding dBTC. A party may hold the vault identifier, the lineage, every public receipt, the encrypted execution capsule, the fulfillment hash, and a copy of every storage replica, and still have no withdrawal authority. Release requires, conjunctively: live dBTC state, valid authority over it, a valid consumption of it, and DLV fulfillment derived from that consumption.

**The chain, top to bottom.**

1. A funded Bitcoin output under a dBTC vault profile.
2. Origin admission: the verifier checks the funding transaction, the outpoint, the amount, the script against the committed profile, chain inclusion, confirmation depth, the recomputed origin identifier, the binding to one canonical DSM issuance position, and the policy commitment. Supply can rise only under a valid origin.
3. Exactly that quantity enters DSM, bound to its origin lineage. A holder's dBTC is a set of origin allocations; the wallet shows one balance, the protocol keeps the provenance.
4. dBTC circulates inside DSM. A transfer is a DSM transition and nothing else: consumed parent, exact credit, provenance preserved. No per-hop fee, no dust floor, no relay, no chain of pre-signed spends.
5. Withdrawal is a consumption first. The holder constructs an exact intent (amount, destination, fee treatment, backing generation and outpoint, successor rule) and burns live dBTC bound to that intent. The burn is a completed DSM transition; the consumed dBTC is not spendable afterwards.
6. Completion evidence exists only for that burn. The vault's unlock secret is derived from the lock, the parameter commitment, and that evidence (`BLAKE3("DSM/dlv-unlock" ‖ L ‖ C ‖ σ)`); its SHA-256 must equal the vault's committed fulfillment hash. The equality is the last check, never the first.
7. Sealed execution authority opens only inside the constrained vault path, bound to the committed transaction. What opens cannot sign anything else.
8. Exactly the committed transaction is signed: a full exit, or a payout plus a **successor vault** holding the remainder under fresh authority, same origin, new generation, new outpoint. A spent parent generation and its successor are never both live backing, and the successor floor is checked at the burn, so a vault can never be drained into dust.

**Four consequences.**

- *No second double-spend system.* DSM already answers whether the state exists and whether it may be consumed; the vault only makes Bitcoin release conditional on that answer. No federation, no signing quorum, no validator set, no global dBTC ledger.
- *Knowledge is not possession.* Copied lineage, copied ciphertext, copied preimage commitment, stale state, a completion proof from another burn, a preimage from another generation: all inert.
- *Storage nodes are librarians.* They hold descriptors, capsules, proofs, and indexes so a future holder can retrieve them. They cannot decide ownership, validate a burn, mint, sign, or pick a successor. Their compromise degrades availability and creates no authority.
- *The depositor never comes back.* After admission the funding party has no role. A later bearer withdraws on the strength of their own dBTC state.

**Two custody domains.** Online dBTC is governed by the canonical economic root and is the only dBTC that SoFi operates on. Offline dBTC is a separately allocated bearer domain using the enrolled appliance and protected-state machinery; it can withdraw by proving its own kind of state, but it never becomes SoFi-spendable liquidity by assertion. Movement between domains happens only through the canonical DSM transition defined for it.

| | Bearer | Offline pay | Sub-dust transfer | Third party in a payment | A compromise costs |
|---|---|---|---|---|---|
| eCash, Cashu, Fedimint | yes | yes | yes | the mint | every coin at the mint |
| Lightning | no | no | yes | counterparty, watchtower | the channel |
| Statechain | yes | no | no | the entity | every coin it touched |
| Ark | no | no | no | the operator | the tree |
| Wrapped / federated | no | no | yes | custodian | everything |
| DSM-native dBTC | yes | yes | yes | none | the holder's own state |

**Not introduced:** a Bitcoin threshold-signing federation, a vault custodian committee, a dBTC validator set, a global dBTC ledger, a mint that approves withdrawals, storage-node economic voting, a second double-spend database, a depositor liveness requirement, wall-clock settlement validity, a dBTC-only ownership model, a dBTC-only hardware appliance, or any rule that knowing a preimage constitutes ownership. **Not claimed:** that DSM prevents a Bitcoin reorganization deeper than the chosen confirmation depth; that dBTC survives compromise of the DSM authority needed to produce a valid burn; that storage unavailability cannot delay retrieval; that testnet or signet shortcuts imply mainnet security.

**Status in this release (from the code, not the paper).** The V1 design above is frozen and the TLA+ models under `tla/DSM_dBTC_*.tla` track it. In the SDK, new BTC→dBTC tap creation and partial exit are **fenced** by `DBTC_PUBLIC_WITNESS_FENCE` in `dsm_sdk/src/handlers/bitcoin_invoke_routes.rs`: the shipped tap derived its spend authority from public data, so it is refused with no override, no environment escape, and no migration path until sealed per-tap authority is bound behind an admitted in-flight consumption. The origin path is fail-closed. All Bitcoin work is on signet; nothing here claims mainnet readiness. Implementation notes: [dBTCimplement.instructions.md](.github/instructions/dBTCimplement.instructions.md); Rust correspondence: [tla/DBTC_RUST_CORRESPONDENCE.md](tla/DBTC_RUST_CORRESPONDENCE.md). The handbook chapter [08-bitcoin-dbtc.md](docs/book/08-bitcoin-dbtc.md) still describes the earlier HTLC model and is scheduled for rewrite.

## Offline anchor appliance — Software Authority, Hardware Identity

Offline bearer transfer needs one thing software cannot provide: a way to tell a physical device from a byte-for-byte clone of it. Everything else, including transfer uniqueness, is already a software property of DSM (the device state is one resource, consumed as a whole; one parent admits exactly one accepted successor). The appliance therefore gives hardware exactly one job, device identity, and keeps it out of every other decision. Paper: [dsm_anticlone.instructions.md](.github/instructions/dsm_anticlone.instructions.md); boot design: [boot_fenced_fused_anchor.tex](docs/papers/boot_fenced_fused_anchor.tex).

**Two identity domains on one phone.** The online domain is the BIP39 seed alone: no hardware, all online DSM operation. The offline domain is a fusion of three factors, and every offline release must be witnessed by all three over the same root-advance message:

| Witness | Where it lives | What it proves |
|---|---|---|
| σ^DSM | the BIP39 seed key on the phone | the holder's DSM authority |
| σ^chip | a PUF-rooted, non-exportable Ed25519 key resident in the TROPIC01 secure element | this physical chip |
| σ^host | a BLAKE3-SPHINCS+ key sealed inside the RP2350 Secure partition, unsealed only under the enrolled firmware measurement | this firmware on this board |

**The appliance.** `dsm-anchor-core` implements the compact three-state machine (prepare, commit, emit, finalize), power-loss recovery, the software-only receiver acceptance predicate, and the protobuf wire protocol. The chip and host witnesses are minted at commit, after a one-way physical counter decrement that is kept 1:1 with the SMT counter, so no valid release witness exists for an origin while that origin is still spendable. A birth fuse and a slot-0 birth cage make first provisioning one-way. The receiver reads no live chip state, no relay session, and no raw counter: it checks signatures over the message.

**TrustZone-M split on the RP2350.** The Secure monitor (`dsm-anchor-secure-monitor`) owns OTP, the host key, the TROPIC01 SPI bus, the physical counter, the prepare/commit/recovery state, and the exact-measurement seal, and exposes exactly one Non-secure-callable gateway with a fixed-slot mailbox. The Non-secure application (`dsm-anchor-nonsecure-app`) owns USB-CDC, protobuf, and host transport, and has no path to any Secure resource. The monitor runs from Secure SRAM after a bootrom load map and locks SAU and ACCESSCTRL before launching the app. Boundary: [SECURITY_BOUNDARY.md](docs/anchor-trustzone/SECURITY_BOUNDARY.md); memory: [MEMORY_MAP.md](docs/anchor-trustzone/MEMORY_MAP.md).

**Receiver-side hardware verification (Path B).** `dsm-anchor-verifier` provides the relay bridge and the exact counter check without depending on libtropic; `dsm-anchor-hw-verifier` drives the real TROPIC01 session over that relay and is the only crate that pulls the sibling libtropic-rs checkout. `dsm-android-anchor` installs the USB appliance into the SDK bridge seam on the phone and exposes the gated device-setup operations.

**Validation status.** From [VALIDATION_MATRIX.md](docs/anchor-trustzone/VALIDATION_MATRIX.md):

| Row | Test | Status |
|---|---|---|
| 0 | bootrom executes the boot-block load map; monitor runs from Secure SRAM | **PASS 2026-07-12** |
| 1a | σ^chip produced by the Secure monitor over SPI0 | **PASS 2026-07-12** |
| 2a | authority op on an unprovisioned board refused fail-closed | **PASS 2026-07-12** |
| 1–15 (rest) | exact-measurement gate, Non-secure denial of OTP/SPI/DMA, single commit, power-loss cases, flash tamper | pending |

In the monitor crate's own words: full-crypto silicon validation is pending a clean TROPIC power cycle. The used-chip bench harness (`dsm-anchor-bench`) runs the non-mutating adoption and prepare/cancel proofs against an already-used chip without moving the counter; its silicon proof log is in [docs/bench-proofs/](docs/bench-proofs/). The TLA+ model `DSM_OfflineAnchorSingleAppliance.tla` covers the single-appliance case.

## Android app and frontend

The wallet is a four-layer stack and no layer skips another: **React frontend → Kotlin container → JNI/SDK (Rust) → core (Rust)**. The frontend is pure rendering; every rule lives in Rust, and the Kotlin layer carries bytes. The container loads `libdsm_sdk.so` (built with cargo-ndk for every ABI and staged by the Gradle `refreshDsmJniLibs` task), serves the React bundle from the APK's assets through a WebView asset loader, and bridges UI and SDK over a binary MessagePort channel carrying Envelope v3 protobuf bytes. BLE commands travel the same way through `ble.command`; the USB anchor appliance is attached through the same bridge seam.

```bash
make android        # rebuild JNI libs, rebuild and copy the frontend bundle, clean Gradle assemble
make android-libs   # only refresh the native libraries
make install        # build and install a debug APK on a connected device
```

Release APKs are signed by the maintainer; CI does not sign or upload them. Handbook: [Architecture](docs/book/04-architecture.md), [BLE testing](docs/book/09-ble-testing.md).

## Storage nodes and the beta fleet

A storage node is index-only persistence: it stores and serves bytes, keeps write-once registers, and never signs, validates, or interprets protocol rules ([ADR 0002](docs/adr/0002-storage-acceptance-is-not-cryptographic-endorsement.md), [ADR 0003](docs/adr/0003-transport-may-be-multi-message-acceptance-remains-atomic.md)). The beta fleet is five nodes in GCP `us-central1` with a quorum of three. The client pins the five members and the quorum in `dsm/src/economic/register.rs` under the `dsm-testnet` network id; the same register profile drives the delivery fan-out, so a message is delivered to exactly the quorum's worth of members. The app ships configured for this fleet.

- Local development nodes: `make nodes-up`, `make nodes-down`, `make nodes-status`, `make nodes-reset` (PostgreSQL required). Handbook: [Storage Nodes](docs/book/07-storage-nodes.md).
- Operators: Terraform and deployment scripts under `dsm_storage_node/`; the release workflow ships a Linux x86_64 binary with its SHA-256.
- Beta admission: the fleet meters device writes, and a beta device needs an operator-side allowance before its first publication succeeds.

## Formal verification

- **TLA+** (`tla/`): `DSM.tla` and the protocol core, bilateral liveness, Tripwire, non-interference, offline finality, the single-appliance offline anchor, economic-register observation, and the dBTC abstract, concrete, and trust-reduction models, each with TLC configs. Claims are indexed in [PROOF_CLAIMS.md](tla/PROOF_CLAIMS.md); run with `tla/run_tlc.sh`.
- **Lean 4** (`lean4/`, toolchain `v4.23.0`): 22 files covering the core theorem set with no `sorry`; the `lean` CI job builds them on every run. A sorry-free build is a build, not a witness; the frame theorems carry their own witnesses and mutation checks.
- **Vertical validation** (`tools/vertical_validation`): `tla-check`, `proof-check`, `property-tests`, `implementation-traces` (transfer chain, signature rejection, fork divergence against the real state machine), `adversarial`, `crypto-kat`, `bilateral-throughput`, `benchmark`, `formal-report`, and `full`. The `formal-validation` CI job runs it.
- **Production safety scan** (`ci/production_safety_checks.sh`): the ban list (wall clock, JSON in protocol paths, hex, envelope version) enforced as a CI gate.

Reports: [docs/reports/](docs/reports/); audits: [docs/audits/](docs/audits/); paper-to-code alignment: [PAPER_ALIGNMENT.md](PAPER_ALIGNMENT.md).

## Development workflow

```bash
make help       # every target
make menu       # interactive
make doctor     # toolchain check
make build      # Rust workspace
make frontend   # React bundle
make typecheck  # onboarding smoke check
make lint       # fmt --check + clippy --all-targets, the second half of any green claim
```

On Windows use `.\scripts\dev.ps1` for the Rust workspace and frontend, and WSL2 for Android builds and the shell helpers.

| Workflow | macOS | Linux | Windows |
|---|---|---|---|
| Rust core / SDK | yes | yes | yes |
| Frontend | yes | yes | yes (Node.js 20+) |
| Local storage node | yes | yes | yes (PostgreSQL) |
| Android APK build / install | yes | yes | WSL2 |
| Anchor firmware (`crates/dsm-anchor-pico`, TrustZone images) | yes | yes | WSL2 |

**The board.** The exact CI test command, run from `dsm_client/deterministic_state_machine/`:

```bash
cargo test --locked --workspace --exclude dsm_storage_node --release -- --nocapture --test-threads=1
```

It runs in `--release` because the shipped profile is what is gated and the crypto property tests scale their case counts up outside debug. `cargo test --lib` is not a board: it never compiles the integration suites. Locally, run the targeted suites for the module you changed, mutation-test any gate you touched, and let CI run the board.

**CI shape.** On every pull request: `rust-gates` (fmt, clippy, safety scan), `rust-test` as a three-way matrix (`dsm`, `dsm_sdk`, `workspace-rest`), `storage-node-postgres`, `formal-validation`, `frontend`, `android-unit-tests`, `embedded` (firmware crates), `lean`, `spdx`, `sbom`, and `docker`. On every push to `main` the exhaustive `rust-board` runs the single command above unchanged. Coverage runs on pushes to `main` and nightly and reports to Codecov. Markdown-only changes are path-ignored. Handbook: [Testing and CI](docs/book/10-testing-and-ci.md).

**Repository rules.** One branch, one topic, descriptive names (`fix/`, `feat/`, `docs/`, `chore/`). No `TODO` markers. No legacy fallbacks beside new code. Every security gate ships with a mutation test that turns a named test red when the gate is removed. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) for reporting vulnerabilities privately.

## Documentation index

- [Developer Handbook](docs/book/README.md) — architecture, setup, protocol reference, storage nodes, testing, command reference, glossary, hard invariants, spec index
- [DSM Primitive](docs/papers/dsm_primitive.pdf) — boundary, definition, and composition of the primitive; [Initial bootstrap](docs/papers/Initial_bootstrap.pdf)
- [Papers and frozen amendments](docs/papers/) — settlement and evidence profile, accepted successor, verification closure, lineage quarantine, exact-output trade intent, receipts, owner catch-up, CCB object registry
- Specifications under [.github/instructions/](.github/instructions/) — SoFi, dBTC, anticlone (anchor), device-tree root lifecycle, recovery and DLV, storage nodes, emissions, token policy readiness, verification, proto
- [ADRs](docs/adr/) — domain separation constructions, storage acceptance, multi-message transport
- [Audits](docs/audits/), [reports](docs/reports/), [bench proofs](docs/bench-proofs/), [anchor TrustZone](docs/anchor-trustzone/)
- [Quickstart](QUICKSTART.md), [Contributing](CONTRIBUTING.md), [Code of Conduct](CODE_OF_CONDUCT.md), [Security](SECURITY.md), [Support](SUPPORT.md), [Changelog](CHANGELOG.md)
- [Proto schema](proto/dsm_app.proto) — the wire format

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
