# Changelog

All notable changes to DSM Protocol will be documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)  
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html)

---

## [Unreleased]

---

## [0.1.0-beta.4] — 2026-11-13

Beta.4 is a clean cut from beta.3. Nothing is migrated: uninstall any earlier
beta before installing this one, and create a new wallet. The network id is
still `dsm-testnet`, and the faucet funds each new account. This release is
for developer onboarding and feedback; it is not for holding value.

### Breaking

- **No state from beta.3 is read.** The device state, the client database, the
  wire formats and the storage fleet all changed, and no migration is
  provided, deliberately: beta carries no production user state, so the remedy
  is a wipe.
- **Identity is rooted in the recovery phrase.** A wallet's genesis is derived
  from its BIP39 phrase, self-attested and published to the fleet (#514). The
  hardware-binding scheme of earlier betas (C-DBRW) and the MPC genesis are
  removed (#514, #992, #1148).
- **A new storage fleet.** Five nodes with a quorum of three, pinned in the
  client. A node stores and serves bytes and keeps write-once registers; it
  validates no protocol rule (#932).
- **SoFi's routes are replaced.** The `dlv.*` and `route.*` routes are gone.
  A vault is created, traded against, resolved and closed through `sofi.*`,
  and every decision is Core's.
- **A token's supply is fixed when it is created.** There is no mint after
  creation.
- **ERA has two decimals** (#1095).
- **Online messages are removed** (#1050).
- **dBTC is being replaced and does not function in this release.** Its code
  stays in the tree and nothing runs it; see the README's dBTC section.

### Added

- **Plug your app into DSM (DSM Connect, DSM Amendment A11).** An app keeps
  its own server and language, gets a DSM account of its own, and its users
  connect their wallets to it under a grant they approve. The app asks a
  wallet for a payment, a proof of what it owns, a sign-in, an item given or
  accepted, a trade or a match (#1112, #1118, #1121). Shipped with it:
  - `dsm-app-host`, prebuilt for Linux (x86-64, ARM64) and macOS (arm64,
    x86-64), installed by `install.sh`, which checks every download against
    `SHA256SUMS`;
  - the TypeScript and Python clients, the Connect starter, and terminal
    wallets for development;
  - the guide, published as pages, and `BUILDING_APPS.md`;
  - an app's account on the beta network by default (`make app-dev`), or on a
    local storage set (`make app-dev-local`);
  - application cells, contributions and a state scope, as generic facilities
    for applications.
- **Offline payments with the appliance.** A phone with the DSM board (RP2350
  with the TROPIC01 secure element) pays another phone with a board over
  Bluetooth with no network. Each offline release carries three signatures
  over the same step: the wallet's, the chip's and the board firmware's. The
  receiver's board takes part too: it checks the payment and commits the
  receive, so a payment is received once. Money is loaded into and unloaded
  from an offline account, money received offline is kept apart until it is
  moved to the balance, and a phone that received offline goes on paying
  offline from what it loaded (#1148, #1226). Installing a board is never
  automatic and is tried first (DSM Amendment A32).
- **SoFi on the device.** A vault is a constant-product market over two
  adopted tokens with a fee in basis points, created from its owner's own
  balances (`sofi.createVault`). A trader finds and prices a route
  (`sofi.findRoute`) and trades through one or two vaults (`sofi.trade`,
  `sofi.route`); a trade interrupted before it finished is completed from what
  storage holds (`sofi.resolve`, `sofi.relay`); the owner closes the vault and
  takes both reserves back (`sofi.close`).
- **Escrow vaults (SoFi Amendment S21).** An amount is locked under named
  outcomes, each naming who decides it and whom it pays, and is released by
  the verdict (#1114). A computed escrow is decided by a pinned program over a
  signed transcript instead of by signers (#1118).
- **Tokens.** Create a token under a policy for a fee in ERA, with coin
  artwork; share it by QR code or anchor; adopt it; burn it. Adoption precedes
  receipt: a device is never credited a token it has not adopted (#871,
  #1110).
- **The faucet.** A new account claims 100 ERA, and the claim is listed in the
  wallet's history (#1018).
- **Wallet.**
  - The recovery phrase is shown when a wallet is created and checked before
    the wallet exists (#1088).
  - Every screen is on the StateBoy frame, with gold, zebra and leopard skins
    (#1028, #1036); the Modern and DGen looks and Simple mode (DSM Amendment
    A17).
  - Contact cards and email receipts (DSM Amendment A17).
  - A hands-on guided tour in practice mode (#973).
  - A debug report through the share sheet (#1107), and a count on the app
    icon of money received and not yet looked at (#1151).
- **iOS app.** The same Rust SDK and the same screens in a Swift container,
  for the Simulator and for a device. It has no board link, so it makes no
  offline payments.
- **Storage nodes.** Long-poll for waiting clients (#1108), arrival records
  and byte commitments (#974), each operator's own certificate authority, and
  one-line setup for a public node.
- **Formal models, checked in CI.** Lean 4 and TLA+ models of the core, SoFi
  and the offline protocol; a formal proof for SPHINCS+ over BLAKE3 (#1120);
  and a Lean proof that no counterfeit value is accepted, online or offline
  (#1149).
- **Build gates.** The build refuses placeholders, fabricated results and
  hidden errors (#1045); every tracked `Cargo.lock` is audited (#889); a
  tagged release runs the full tests and a newcomer's first run on a clean
  machine before it publishes.

### Changed

- **Acceptance is one hop (DSM Amendment A14).** A receiver validates a peer's
  step from that step's own parent and reads nothing behind it.
  `ci/acceptance_lock.py` enforces this in CI.
- **One device state.** The per-device state and its sparse Merkle tree
  replace the hash chain and the state number, which are deleted.
- **Online payments.** The signed operation is the only authority, with one
  ingestion boundary (#1048); a send is kept in a durable outbox and finalized
  atomically; a payment settles in seconds (#1107).
- **Bluetooth and USB carry offline payments only.** The radio, its addresses
  and pairing belong to the native layer; the frontend renders what Rust
  reports (#1021, #1023, #1030).
- **The frontend renders only.** The wallet's decisions (app lock, pair order,
  token fields) moved into Rust.
- **One pinned Rust toolchain,** enforced in CI.

### Removed

- C-DBRW hardware binding, and its fields on the wire (#514, #1148).
- The MPC genesis (#992).
- The hash chain, the state number and the legacy state machine API.
- The earlier secure-element relay design for offline payments, replaced by
  the appliance.
- SoFi's pre-signed fallback and slippage floors, and the earlier `dlv.*` and
  `route.*` settlement paths.
- The PaidK gate (#965).
- Online messages (#1050).
- Code that reported success without doing the work (#964, #966, #992).

### Security

- **Security audits of 2026-10-15, 2026-10-18 and 2026-11-12,** with their
  fixes (#1139, #1142, #1152).
- **A transfer's memo, ticker and nonce are in no public object** (#1102).
- **The ML-KEM key delivered over Bluetooth is authenticated** against the
  pinned identity key before it is cached.
- **Storage node:** every `/admin` endpoint is behind the admin token, and the
  admin and gossip tokens fail closed when unset (#421, #422).
- **Hostile input is bounded:** over-long proofs, trailing bytes in decoders
  and oversized Bluetooth reassembly are refused (#428, #429, #430, #431,
  #450).
- **Builtin ERA cannot be issued** at the accepting transition.
- **Dependency advisories fixed:** rustls (#887), quinn-proto and quinn-udp
  (#889, #1227), ctutils (#1155), crypto-bigint (#1148).

### Not in this release

- dBTC (being replaced).
- Offline payments on iOS (no board link).
- Token emissions beyond the faucet: the schedule is in Core only.
- The Android APK is not built by the release workflow; the maintainer signs
  and uploads it.

---

## [0.1.0-beta.3] — 2026-04-22

Major architectural release. **215 commits, 525 files, +66.7k/-43.1k lines** since beta.2. Reshapes the state model around `DeviceState`, unifies the native ingress boundary across platforms (iOS scaffolding added), purges ~10,000+ lines of legacy code, and hardens APK signing to v2+v3+v4.

### Architectural changes

- **`DeviceState` is now the canonical state model** — `State` is a derived view computed from `DeviceState`. `StateMachine` stripped to bare minimum (`DeviceState` + `relationship_manager`). The old dispatch surface (`execute_transition`, `execute_dsm_operation`, `apply_operation`) is gone. All operations — bilateral transfers, mint, burn, fee transfers, DLV unlock, smart commitments — now route through a single uniform `CoreSdk::execute_on_relationship` API. The `advance` path split into `prepare / commit / restore` semantics for cleaner recovery and settlement.
- **Unified ingress boundary across platforms** — the legacy `appRouter` dispatch is gone. All protocol traffic now flows through `dsm_sdk::ingress` (~1,460 LOC) with platform-specific ABI shims on top. Android JNI (`unified_protobuf_bridge`) routes envelope / router / hardware-facts calls through the shared ingress.
- **iOS scaffolding** — C FFI surface exported via `dsm_process_envelope_protobuf` / `dsm_free_envelope_bytes`. Platform scaffolding under `dsm_sdk/src/platform/ios/{bluetooth,transport}.rs`. iOS integration documented in `docs/book/11-integration-guide.md`. (iOS app itself is not yet shipped.)
- **Two new Android bridges** — `NativeBoundaryBridge` for DSM native ingress/startup and `NativeHostBridge` for host-capability requests (QR, BLE, NFC, permissions, biometric).
- **§4.3 spec compliance: `state_number` purged from canonical hash paths** — removed from the `State` struct and every canonical hash input across `dsm` and `dsm_sdk`. Identity logic switched to hash-based IDs. Multiple §4.3-violating call sites deleted (including the broken `get_state_by_number` helper, with 5 callers migrated).

### Added

- **NFC recovery pipeline** — capsule v4 format, persisted recovery key, SMT-root capsule reuse, full identity restore flow. NFC handling inlined in the bridge; standalone NFC activities removed.
- **`bitcoinTap` vault summaries** — storage path switched to BitcoinTap-style vault summaries.
- **Recovery tombstone codec migrated to protobuf** (previously bincode) — aligns with the repo's "protobuf-only in protocol paths" invariant.
- **GATT identity read flow** — `observeGattIdentityRead` JNI/Kotlin path; BLE event relay now allows callers to mark transient events droppable when the bridge is unavailable.
- **Expanded BLE hardening** — peer identity hydration from persisted contacts for stale BLE addresses; multi-peer fallback address resolution with coordinator tests; session-lifecycle locking (`TEST_DB_LIFECYCLE_LOCK`); BLE session recovery routed through canonical SMT; BLE foreground service wakes on stitched-receipt cache hit.
- **Contact export** — `export_contacts` overlays persisted `chain_tip` + `ble_address` instead of dropping them behind stale in-memory state.
- **APK signing schemes v3 and v4** — release APKs now carry v2, v3, and v4 signatures (v1/JAR disabled; minSdk 24 doesn't require it). v4 emits an `.idsig` file alongside the APK for incremental install on Android 11+.
- **Interactive APK signing flow** — `make android-release` now prompts for keystore path, key alias, keystore password, and key password on an interactive TTY; env-var and gradle-property overrides supported.
- **Expanded test coverage** — unit coverage added for storage-node API & replication, SDK storage & bilateral, core crypto, frontend wallet/hooks/services/utils, Android bridge/BLE/security (JVM).
- **Formal verification expansion** — vertical-validation property tests extended; SPHINCS+/BLAKE3 deterministic-signing and cross-domain-digest retarget-rejection property tests added; all 10 previously-ignored security/verification tests fixed and passing; TLA+ runs (`DSM_tiny`, `DSM_small`, `DSM_system`, `Tripwire`) pass on the release commit.
- **`caveman-compress`** plugin + tool for docs/prose compression.

### Changed

- **Release keystore format** — signing keystore default switched from JKS to PKCS12 (`.p12`), aligning with the Java 9+ default and keytool recommendations.
- **Android beta version alignment** — release APK reports `versionCode = 3` and `versionName = 0.1.0-beta.3`.
- **Wallet UI polish** — transaction cards show aliases + amount on own line, expanded views keep full hashes, faucet/history cards no longer balloon on small screens.
- **Bridge readiness sequencing** — frontend identity loading now waits for `dsm-identity-ready` instead of `dsm-bridge-ready`.
- **Rust toolchain switched to stable** — no more nightly dependency.
- **CI guardrails rewritten for fork architecture** — `enforce-guardrails` and flow assertions updated for unified ingress.

### Fixed

- **Online send false "SMT proofs are invalid"** — `wallet.send` uses `smt_proofs.pre_root` when constructing first-advance receipt commitments.
- **Pixel 9 faucet brick** — §4.3-violating monotonic `state_number` check removed from faucet path.
- **Faucet phantom token row** — credits no longer render a stale ERA = 0 row.
- **SendTab error surface** — offline transfer failures now show the real reason instead of a generic "Offline transfer failed."
- **Settlement stale-tip cleanup** — successful bilateral settlement clears stale observed-remote-tip claims so converged relationships don't block behind old live-peer mismatches.
- **Sender-session persistence fail-closed** — BLE sender session registration aborts on persist errors instead of continuing in-memory-only.
- **Frontend startup regressions** — stale frontend tests repaired after the ingress migration; identity readiness now reflects the active startup flow.

### Security

- **DLV settlement anchoring enforced** — token operations now require anchored DLV settlement.
- **Real signature checks in verification** — replaces prior placeholder paths.
- **Malformed token-id rejection** — balance-key derivation hard-fails on malformed token IDs instead of admitting ambiguous keys; duplicate hardening in balance checks.
- **Canonical identity binding** — identity store and invalidation are bound to canonical genesis IDs; prevents cross-identity contamination.
- **`ThermalStateProto` removed** — obsolete residue from an old transport schema; kept the live protocol surface singular.
- **Dependency surface reduction** — `dsm` core crate no longer pulls certificate-generation, host/network-discovery, async utility, or wall-clock crates for normal builds.
- **Dependabot alerts closed** — upgraded handlebars to 4.7.9, closing 7 advisories.

### Legacy code purge (~10,000+ LOC deleted)

Made possible by the `DeviceState` migration:

| Area | LOC deleted |
|---|---:|
| `HashChain` infrastructure | ~3,200 |
| `BCR` heuristic detection | ~1,200 |
| `hierarchical_device_management` module | ~1,180 |
| `protocol_metrics.rs` | ~1,362 |
| `chain_tip_sync_sdk` module | ~787 |
| `BilateralStateManager` dead session/chain-tip surface | ~280 |
| `StateMachine` verification helpers | ~210 |
| Dead `State` / `RelationshipManager` / `RelationshipStatePair` methods | ~600+ |

Also removed: `DualModeVerifier`, `state_to_wire`, `random_walk` state helpers, `verify_trustless_identity`, `resume_relationship`, `create_token_state_transition`, `ContactManager::update_contact_from_transition`, `State` struct fields (`external_data`, `hashchain_head`, `matches_parameters`, `state_type`, `value`, `commitment`), plus 10+ zero-caller `State` methods.

### Dependencies

tokio `1.50 → 1.51`, hyper `0.14 → 1.8`, axum `0.8.8 → 0.8.9`, axum-server `0.7.3 → 0.8.0`, rustls-native-certs `0.7.3 → 0.8.3`, tokio-postgres `0.7.16 → 0.7.17`, tokio-postgres-rustls `0.12.0 → 0.13.0`, hmac `0.12.1 → 0.13.0`, uuid `1.22 → 1.23`, mockall `0.12.1 → 0.14.0`, toml_edit `0.22.27 → 0.25.8`, handlebars `→ 4.7.9`. Frontend: react-dom, `@types/node`, `@typescript-eslint/parser`, copy-webpack-plugin, webpack-cli, mini-css-extract-plugin. CI: codecov-action v6, upload-artifact v7.

---

## [0.1.0-beta.2] — 2026-04-06

Targeted hardening release focused on bilateral BLE reliability. 121 files changed, +5.6k/-3.6k lines.

### Fixed

- **Bilateral BLE confirm flow** — BLE confirm delivery is now revised and persisted across app restarts. Pending confirms are cleared after a successful `BilateralCommitResponse` in `handle_commit_response`, preventing duplicate delivery on reconnect.
- **Frontend session-status polling** — switched `pollSessionStatus` from `setInterval` to a self-scheduling `setTimeout`, eliminating overlapping async polls and the race conditions they caused.
- **SQLite modal recovery** — SQLite modal recovery now runs before rejecting operations, reducing false-negative rejections when the DB was mid-recovery.

### Changed

- **BLE bilateral handler refactor** (PR #140) — `bilateral_ble_handler.rs` and `bilateral_full_offline_flow.rs` reworked around the revised confirm lifecycle; BLE relationship-status handling and toolchain checks tightened.
- **TLA+ replay tools** — `deviceBalance` added to TLA specs and replay tools to make balance-sensitive invariants checkable in replay.

### Added

- **PII scan in preflight** — developer preflight now scans for PII before tooling runs.

### Removed

- **SoFi examples** — legacy SoFi example code dropped from the tree.
- **`fix_bridge.patch`** — stale patch file removed.

---

## [0.1.0-beta.1] — 2026-02-19

### Added
- **Bilateral BLE offline transfer** — two-device token transfers over Bluetooth LE with no internet connection required; full state-machine handshake with cryptographic verification on both ends
- **Deterministic state machine core** — hash-chained transaction history with no server-side state; each state transition is irreversible and cryptographically bound to the previous
- **DSM SDK (Rust)** — JNI-exposed library for Android providing wallet management, token operations, BLE transport, and storage-node communication
- **Local storage nodes** — five-node SQLite-backed storage layer with deterministic hashing-based assignment and configurable replication
- **Android client** — React Native/WebView hybrid app with hardware-backed key storage, BLE pairing flow, and integrated diagnostics overlay
- **Local Bitcoin test tooling** — deterministic test-faucet utilities enabled only in early test/debug builds
- **16 KB page-size support** — native libs built with `-Wl,-z,max-page-size=16384` for Android 15+ high-RAM device compatibility
- **`make` build system** — single Makefile entrypoint for all developer tasks (`make help` for full list)

### Changed
- All storage-node endpoints default to `127.0.0.1` (loopback via `adb reverse`) instead of a LAN IP
- Version bumped from `0.1.0` to `0.1.0-beta.1` across all crates, Android app, and frontend

### Security
- Removed hardcoded RSA public key from `storage_node_config.toml`; replaced with placeholder
- `.cargo/config.toml` (machine-local NDK paths) is now gitignored; use `make setup` to generate from template
- `.so` build artifacts are gitignored and must be built locally via `make android-libs`

---

[Unreleased]: https://github.com/deterministicstatemachine/dsm/compare/v0.1.0-beta.3...HEAD
[0.1.0-beta.3]: https://github.com/deterministicstatemachine/dsm/compare/v0.1.0-beta.2...v0.1.0-beta.3
[0.1.0-beta.2]: https://github.com/deterministicstatemachine/dsm/compare/v0.1.0-beta.1...v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/deterministicstatemachine/dsm/releases/tag/v0.1.0-beta.1
