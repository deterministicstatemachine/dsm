# Chapter 10 — Testing and CI

Test suites, CI pipeline, E2E tools, and code quality gates.

---

## Test Suites Overview

| Suite | Command | Scope |
|-------|---------|-------|
| Rust workspace | `cargo test --workspace --all-features` | Core, SDK, storage node, and broader integration coverage |
| Core crate | `cargo test --package dsm` | Protocol logic, crypto, state machine |
| SDK crate | `cargo test --package dsm_sdk` | JNI dispatch, bilateral, BLE, storage |
| Storage node | `cargo test --package dsm_storage_node` | API handlers, replication |
| Frontend (Jest) | `cd dsm_client/new_frontend && npm test` | React components, bridge, contexts, and broader UI/Jest coverage |
| Android (JUnit) | `cd dsm_client/android && ./gradlew :app:testDebugUnitTest` | Kotlin unit tests |
| Android (device) | `cd dsm_client/android && ./gradlew :app:connectedDebugAndroidTest` | Instrumented tests |
| Bitcoin E2E | `cargo test --package dsm_sdk --test bitcoin_tap_e2e -- --test-threads=1` | Signet-oriented swap coverage |
| BLE E2E | `python3 tools/ble_pairing_e2e.py` | Physical device BLE pairing |
| Offline E2E | `python3 tools/offline_send_e2e.py` | Physical device bilateral transfer |

## Quick Onboarding Validation

For initial machine bring-up, prefer the same supported smoke checks used in the quickstart:

```bash
make build
make typecheck
```

If you touch DLV, policy, or generated-client workflows, also verify the generator entry point:

```bash
cargo run -p dsm-gen -- --help
```

Use the full `make test`, `cargo test --workspace`, and `npm test` suites after the toolchain is up; they cover broader integration scenarios than the onboarding smoke check.

---

## Rust Tests

### Run All Tests

```bash
cargo test --workspace --all-features
```

Some SDK integration tests reach the configured storage network. If you only need fast local compile validation or you are working offline, prefer `make build`, `cargo test --workspace --all-features --no-run`, or focused package tests.

### Run Specific Crate

```bash
cargo test --package dsm           # core only
cargo test --package dsm_sdk       # SDK only
cargo test --package dsm_storage_node  # storage only
```

### Run Specific Test

```bash
cargo test --package dsm --lib -- test_name --nocapture
```

### Compile-Only Check (Fast)

```bash
cargo test --workspace --all-features --no-run
```

### Bitcoin Integration Tests

Bitcoin coverage now targets the signet-backed flow and does not require a local Bitcoin node:

```bash
cargo test --package dsm_sdk --test bitcoin_tap_e2e -- --test-threads=1 --nocapture
```

---

## Frontend Tests

### Jest Suite

```bash
cd dsm_client/new_frontend
npm test                          # run all tests
npm test -- --watch               # watch mode
npm test -- --coverage            # with coverage report
npm test -- --passWithNoTests     # pass if no test files found
```

For initial environment validation, start with `npm run type-check`; `npm test` is the broader Jest suite.

### TypeScript Type-Check

```bash
cd dsm_client/new_frontend
npm run type-check                # tsc --noEmit
```

### Lint

```bash
cd dsm_client/new_frontend
npm run lint                      # ESLint check
npm run lint:fix                  # auto-fix
```

---

## Android Tests

### Unit Tests (JUnit + Robolectric)

```bash
cd dsm_client/android
./gradlew :app:testDebugUnitTest
```

### On-Device Tests

Requires a connected Android device:

```bash
cd dsm_client/android
./gradlew :app:connectedDebugAndroidTest
```

---

## E2E Test Tools (Python)

Physical device tests using Python automation scripts in `tools/`.

### Prerequisites

- Python 3.9+
- Two Android devices connected via ADB
- DSM Wallet installed on both (debug build)
- Storage nodes running
- ADB reverse port forwarding configured

### Complete E2E Sequence

```bash
# 1. Build and install
make install

# 2. Run smoke test (pairing + persistence)
python3 tools/live_smoke_orchestrator.py \
  --device1 <SERIAL_A> --device2 <SERIAL_B>

# 3. Run offline transfer
python3 tools/offline_send_e2e.py \
  --device1 <SERIAL_A> --device2 <SERIAL_B> \
  --amount 1000000000 --timeout 60

# 4. Verify persistence
python3 tools/verify_persistence.py \
  --device1 <SERIAL_A> --device2 <SERIAL_B>
```

---

## CI Gates

### Gate Scripts

| Script | What It Checks |
|--------|---------------|
| `scripts/ci_scan.sh` | Banned patterns (TODO, FIXME, HACK, XXX), hex in protocol, JSON in protocol |
| `scripts/flow_assertions.sh` | Data flow invariants (single authoritative path) |
| `scripts/flow_mapping_assertions.sh` | Flow mapping correctness |
| `scripts/guard_protos.sh` | Protobuf types in sync between proto file and generated code |
| `scripts/codegen_enforce.sh` | Codegen rules (no manual proto edits) |

### Run All CI Gates

```bash
make ci-scan
```

Or individually:

```bash
bash scripts/ci_scan.sh
bash scripts/flow_assertions.sh
bash scripts/flow_mapping_assertions.sh
```

### Proto Guard

Verifies that generated protobuf types match the `.proto` source:

```bash
make proto-guard
```

If this fails, regenerate:
```bash
cd dsm_client/new_frontend && npm run proto:gen
```

### Flow Assertions (Stack Order-of-Operations)

The flow assertion scripts act as a regression gate for stack order-of-operations. They verify that required anchors exist across all layers.

**Required anchors** (must exist in the codebase):

- **Frontend online invoke path:**
  - `transactions.ts` has `sendOnlineTransfer(...)`
  - `transactions.ts` routes through `appRouterInvokeBin('wallet.send', ...)`
- **Frontend offline bilateral path:**
  - `transactions.ts` has `offlineSend(...)`
  - `transactions.ts` routes through `bilateralOfflineSendBin(...)`
  - `WebViewBridge.ts` maps to `methodName: 'bilateralOfflineSend'`
- **Framed router boundaries:**
  - `WebViewBridge.ts` emits bridge methods `appRouterInvoke` and `appRouterQuery`
  - JNI exposes `appRouterInvokeFramed` and `appRouterQueryFramed`
- **Async native event pipeline:**
  - `index.html` includes `dispatchEventPayload(bytes)` and emits `dsm-event-bin`
  - `EventBridge.ts` listens to `dsm-event-bin`
  - `EventBridge.ts` handles `bilateral.event` and `ble.envelope.bin`
- **SDK router handler anchors:**
  - `app_router_impl.rs` includes `process_online_transfer_logic`
  - Query routes include `contacts.handle_contact_qr_v3`, `inbox.pull`, and `bilateral.pending_list`

**CI integration:**

- `ci.yml` runs `bash scripts/flow_assertions.sh` in the build job
- `ci.yml` runs `bash scripts/flow_mapping_assertions.sh` in the build job
- `Makefile` target `ci-scan` runs both plus `scripts/ci_scan.sh`
- Local: `make flow-assertions` and `make flow-mapping-assertions`

**Update policy:** If any anchor changes intentionally:

1. Update code first
2. Update `scripts/flow_assertions.sh` patterns to match the new canonical symbols
3. Update `scripts/flow_mappings.manifest` entries for exact mapping changes
4. Run `make flow-assertions`, `make flow-mapping-assertions`, and `make ci-scan` before merging

All checks are string/structure-based and deterministic (no wall-clock logic).

---

## Code Quality

### Rust Linting

```bash
# Format check
cargo fmt --all -- --check

# Clippy (warnings are errors in CI)
cargo clippy --all-targets -- -D warnings

# Auto-format
cargo fmt --all
```

### Security Audit

```bash
# cargo-audit (known vulnerabilities)
cargo audit

# cargo-deny (licenses + advisories)
cargo deny check

# Combined
make audit
```

### License Check

```bash
make deny
```

Verifies all dependencies are compatible with MIT OR Apache-2.0.

---

## Banned Patterns

CI scans enforce these bans. Any match is build-blocking:

| Pattern | Why Banned |
|---------|-----------|
| `TODO`, `FIXME`, `HACK`, `XXX` | Production-quality mandate |
| `JSON.stringify`, `JSON.parse` | No JSON in protocol |
| `serde_json` (in protocol code) | Protobuf-only transport |
| `hex::encode`, `hex::decode` | No hex in core (Base32 Crockford at boundaries) |
| `Date.now()`, `SystemTime::now()` | No wall-clock time in protocol |

Check manually:
```bash
git grep -rn "TODO\|FIXME\|HACK\|XXX"
# Must return 0 results
```

---

## Test Device Reference

| Role | Serial | Model | Notes |
|------|--------|-------|-------|
| Device A (Sender) | `<DEVICE_A_SERIAL>` | Android sender device | Use `adb devices` to discover the serial on your machine |
| Device B (Receiver) | `<DEVICE_B_SERIAL>` | Android receiver device | Use a second connected Android device |

---

## Makefile Test Targets

| Target | Description |
|--------|-------------|
| `make test` | Rust + frontend tests |
| `make test-rust` | Rust tests only |
| `make test-frontend` | Frontend Jest tests only |
| `make typecheck` | TypeScript type-check |
| `make lint` | All linters (fmt, clippy, ESLint) |
| `make audit` | Security audit |
| `make ci-scan` | CI gate scripts |

---

Next: [Chapter 11 — Integration Guide](11-integration-guide.md)
