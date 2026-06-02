# DSM AI Coding Agent Instructions
## Current Audit Baseline
**Audit baseline:** February 24, 2026
Treat the following invariants as satisfied at this baseline. Every change must preserve them.
- All hard invariants compliant.
- Production safety violations resolved, including no panics or unchecked expects in production paths.
- dBTC balance bug fixed.
- Hex encoding violations remediated in favor of Base32 Crockford where string transport is unavoidable.
- Compilation clean across all packages.
- Test infrastructure updated for fallible constructors.
Never claim a scan, build, test, proof, or diff check passed unless it was actually run in the current workspace and the output was inspected. If a check cannot be run, state exactly which checks remain unrun.
---
# Production-Quality Mandate
Ship a complete, production-quality DSM implementation that exactly matches `WHITEPAPER.md`.
No mocks.
No stubs.
No placeholders.
No TODOs.
No fallbacks.
No deprecated paths.
No compatibility shims unless explicitly approved as a temporary migration exception with a removal issue and CI guard.
Any change that replaces a path must remove the old path in the same change. Deprecated aliases, fallback decoders, dual-routing code, legacy constructors, and compatibility branches are rejected unless they are explicitly listed as temporary migration exceptions.
`WHITEPAPER.md` is the source of truth. If code and `WHITEPAPER.md` drift, the code changes.
---
# Encoding Rule: No Hex
DSM is binary-first.
## Allowed
- Protobuf Envelope v3 bytes end-to-end inside the system.
- Raw bytes internally.
- Base32 Crockford for human-facing or copy/pasteable string representation at platform boundaries.
- Base64 only when a platform API requires opaque binary protobuf blobs to cross a string-only bridge. Base64 may wrap the entire protobuf blob only. It must never represent individual protocol fields.
- UI-only display formatting may render 32-byte identifiers in a human-readable way, but anything copy/pasteable must be Base32 Crockford and must never be accepted back into Core or SDK as protocol input.
## Not Allowed
- Hex in any persisted schema, bridge payload, envelope field, storage object, protocol object, or accepted input.
- Hex as accepted input to Core or SDK APIs.
- Hex encode/decode usage in Core, SDK, JNI, storage, or bridge logic.
- Base64 inside Core or canonical protocol paths.
- JSON codecs, JSON envelopes, dual formats, or stringly protocol fallbacks.
## Summary
Bytes inside.
Protobuf Envelope v3 as the only system container.
Base32 Crockford at human/copy/paste boundaries.
Base64 only for whole-protobuf transport through string-only platform APIs.
Hex is display-only diagnostics at most, never accepted back into protocol logic.
---
# Determinism and Clockless Semantics
Hard stop: no wall-clock markers in protocol semantics.
No wall-clock markers are permitted in:
- Schemas.
- Payloads.
- Receipts.
- Acceptance predicates.
- Commitment bytes.
- Chain ordering.
- Protocol-state transitions.
- Protocol logs.
- Protocol metrics.
- Storage records.
- Canonical hashes.
- Canonical signatures.
Ordering is only by:
- Straight Hash Chain adjacency via `chain_tip`.
- Domain-separated BLAKE3 iteration or work counters.
BLE transport/runtime may use wall-clock time only for operational behavior:
- Retries.
- ACK timeouts.
- Reconnect backoff.
- Pacing.
- Idle expiry.
- Handshake freshness.
- Stale-session recovery.
- Transport DoS controls.
- Local elapsed-time transport diagnostics.
Those values must never enter protocol state, storage, commitments, signatures, ordering, receipts, or acceptance predicates.
Any time API that affects protocol semantics is a build-blocking violation.
---
# Encoding, Transport, and Canonicalization
## Envelope v3 Only
- Protobuf Envelope v3 is the sole protocol container.
- Envelope header `version == 3`.
- Tag 2 is reserved and must never be reintroduced for wall-clock marker fields.
- Wrong version, unknown fields, deprecated fields, or reserved fields must hard fail.
- Transport-only BLE framing below Envelope v3 is permitted only if it remains opaque to protocol semantics and carries no protocol meaning beyond byte delivery.
## Required Fields
Required protocol fields:
- `device_id`: `bytes[32]`
- `chain_tip`: `bytes[32]`
Rules:
- `device_id` is always raw 32 bytes inside protocol logic.
- `chain_tip` is normalized to exactly 32 bytes.
- UI may render Base32 Crockford for display/copy only.
- Core and SDK must never accept rendered identifiers as protocol input.
## Canonical Bytes
- Canonical bytes are produced by the Core canonicalizer.
- SDK canonicalization must mirror Core exactly.
- Canonical bytes must be bit-stable across platforms.
- No JSON, CBOR, base64, hex text, or non-deterministic serializer may enter canonical bytes.
- Strict-fail decoding is mandatory.
---
# Protocol Boundaries and Single Path
There is one authoritative path:
UI/WebView → MessagePort → Kotlin Bridge → JNI → SDK → Core
No side channels.
No alternative routes.
No deprecated send path.
No direct Kotlin calls from TypeScript.
No JSON envelope route.
No bypass around Core.
## Core
Core is pure.
Core must not contain:
- Network access.
- OS time.
- UI logic.
- Global mutable protocol state.
- Storage-node trust assumptions.
- Platform bridge interpretation.
Core owns:
- State transitions.
- Cryptography.
- Validation.
- Ordering.
- Policy enforcement.
- Canonicalization.
- Tripwire enforcement.
- DBRW checks.
- DLV unlock predicates.
## SDK
SDK mediates I/O and calls Core.
SDK must not create alternative protocol semantics.
## Storage Nodes
Storage nodes are index-only mirrors.
Storage nodes:
- Store bytes.
- Serve bytes.
- Index bytes.
- May reject malformed protobuf objects.
- Never sign.
- Never validate protocol acceptance.
- Never gate DLV unlocks.
- Never affect unlock predicates.
- Never decide correctness.
---
# Layer Communication Law
## Kotlin Is Transport-Only
Kotlin shuttles:
`[8-byte msgId][protobuf]`
between WebView MessagePort and Rust JNI.
Kotlin must not:
- Interpret envelope contents.
- Validate envelope fields.
- Transform protocol bytes.
- Make protocol decisions.
- Cache protocol state that belongs in Rust.
- Decide protocol outcomes.
The only exceptions are OS-required hardware access paths such as BLE, NFC, and sensors. Even then, hardware data must be relayed to Rust via JNI for protocol decisions.
## TypeScript Is Rendering-Only
TypeScript:
- Renders UI.
- Sends and receives binary protobuf envelopes through MessagePort.
- Does not perform protocol validation.
- Does not call Kotlin outside the MessagePort binary bridge.
- Does not maintain protocol state.
- Does not create JSON envelopes.
## Rust Is the Sole Protocol Authority
Rust owns all:
- Crypto.
- Validation.
- State transitions.
- Ordering.
- Canonicalization.
- Policy enforcement.
- DBRW enforcement.
- DLV math.
- Tripwire fork exclusion.
## BLE Transport Clarification
BLE transport/runtime layers may track:
- Session IDs.
- Message IDs.
- Chunk windows.
- Retransmit state.
- ACK/NACK progress.
- Operational wall-clock timers.
BLE must emit either:
- One completed protobuf payload, or
- One typed transport failure.
BLE must not emit protocol conclusions.
## Regression Signals
Any of the following is a violation:
- Kotlin inspecting protobuf field values beyond method routing.
- Kotlin validating protocol fields.
- Kotlin deciding protocol outcomes.
- Kotlin caching protocol state that belongs in Rust.
- TypeScript calling Kotlin outside the MessagePort binary bridge.
- TypeScript sending JSON envelopes.
- Business logic in Kotlin.
- Alternative protocol path around JNI/Core.
- Deprecated send route.
- Dual transport.
---
# Cryptography and Security
- BLAKE3 is used everywhere with explicit domain separation.
- SPHINCS+ signatures are used where signatures are required.
- Signature verification must be constant-time where applicable and must not create FFI timing leaks.
- PQ KEM, where used, must be Kyber/ML-KEM per spec.
- No `unsafe` in hot paths.
- If `unsafe` is unavoidable, it must be audited, fenced, minimal, and justified in comments.
- Tripwire fork exclusion must run on every parent tip.
- Duplicate parent consumption must reject deterministically.
- DBRW device/environment binding must be enforced wherever required.
- No DBRW stubs.
- No observe-only DBRW mode unless explicitly specified by the whitepaper for that exact path.
- No cryptographic placeholders.
- No fake randomness.
- No fallback crypto.
---
# Data, State, and Storage
- State is bilateral.
- Per-device SMTs commit relationship tips.
- Straight Hash Chain tips drive evolution.
- DLVs are sovereign vaults.
- DLV unlocks are mathematical and unilateral on proof existence.
- External commitments coordinate atomic multi-vault routes.
- No mempool.
- No validators.
- No sequencers.
- No MEV path.
- No storage-node authority.
---
# Errors, Logging, and Metrics
- Strict-fail behavior is mandatory.
- Errors must use versioned error codes and typed payloads.
- No best-effort protocol acceptance.
- No silent coercions.
- No fallback decoders.
- No panics in production paths.
- No unchecked `expect` in production paths.
- Logs must be structured key-value logs.
- Logs must never leak secrets.
- Behavior must never depend on log level.
Protocol logs, protocol metrics, storage records, receipts, schemas, commitments, and acceptance predicates must not contain wall-clock markers.
Transport diagnostics may record local elapsed durations only inside approved transport/runtime modules. Those values must never enter protocol state, storage, commitments, ordering, or acceptance.
Use deterministic identifiers, chain tips, chain heights, state indices, and BLAKE3 iteration counters instead of wall-clock markers.
---
# Versioning and Compatibility
- Envelope v3 is locked.
- No fallback to Envelope v2.
- No dual transport.
- No silent coercions.
- Schema evolution is additive behind version gates.
- Reserved fields must remain reserved.
- Numeric tags must never be repurposed.
- Tag 2 remains reserved.
- Unknown fields hard fail where strict canonical decoding is required.
- Deprecated paths are removed in the same change that replaces them.
---
# Build, CI, and Quality Gates
- Reproducible builds are required.
- Warnings are errors.
- Compilation must be clean across all packages.
- CI must fail on banned APIs and banned strings.
- CI must fail on codegen drift.
- CI must fail on protocol wall-clock markers.
- CI must fail on JSON envelopes.
- CI must fail on alternative routes.
- CI must fail on hex/base64 misuse in Core.
- CI must fail on unaudited `unsafe`.
Required coverage:
- Canonicalization.
- Encode/decode round trips.
- Cross-language canonical byte equality.
- Fork rejection.
- Duplicate parent rejection.
- DBRW checks.
- DLV unlock proofs.
- dBTC withdrawal/refund invariants.
- No protocol time usage.
- No legacy path creep.
---
# Always-On Integration Mandate
Every change, including a one-line change, must include:
1. Exact files/modules to modify.
2. Pre-change scans.
3. Post-change proofs.
4. Schema/codegen/bridge/test drift verification.
5. Explicit statement of removed legacy paths.
6. Exact tests run, with failures reported honestly.
If any required check fails, the change is invalid until fixed.
---
# Artifact References for Every Instruction
Each coding-agent instruction must cite the relevant artifacts below.
## Protobuf and Codegen
Files:
- `proto/dsm.proto`
- `proto/dsm_app.proto`
- `proto/envelope.proto`
- `src/proto/dsm_app_pb.js`
- `src/proto/dsm_app_pb.d.ts`
- `dsm_client/android/src/main/proto/**`
- `sdk/go/dsmpb/**`
- `sdk/swift/**`
Checks:
- Envelope header `version == 3`.
- Tag 2 reserved.
- `device_id` is `bytes[32]`.
- `chain_tip` is `bytes[32]`.
- No `peer_id`.
- No Envelope v2.
- No JSON envelope fields.
- No wall-clock marker fields.
- No hex/string protocol identifiers.
Regenerate and diff:
```bash
pnpm --filter dsm-wallet run proto:gen
git diff --exit-code

Core Rust

Files:

* core/src/envelope.rs
* core/src/state_machine.rs
* core/src/crypto/**
* core/src/proto/**

Checks:

* Bit-stable canonicalization.
* No protocol time APIs.
* No JSON codecs.
* No hex/base64 encode/decode in Core.
* Signatures verified per guard outside post-state hash.
* Tripwire on duplicate parents.
* DBRW enforced where required.
* DLV proofs strict-fail.
* No production panics.
* No unchecked production expect.
* No unaudited unsafe.

SDKs and Bridges

Files:

* dsm_client/android/**
* dsm_client/android/**/BridgeEnvelope.kt
* dsm_client/android/**/DsmNativeWrapper.kt
* dsm_client/android/**/BLE/**
* dsm_client/android/**/QR/**
* jni/native_wrapper.cpp
* packages/bridge/**
* sdk/swift/**

Checks:

* No JSON envelopes.
* Base64 only at I/O boundary for whole protobuf blobs.
* Base32 Crockford for copy/pasteable human-facing strings.
* Single path: UI → MessagePort → Kotlin Bridge → JNI → SDK → Core.
* Kotlin transport-only.
* TypeScript rendering-only.
* Rust protocol authority.
* BLE transport timers only in approved transport/runtime files.

Storage Index Tier

Files:

* storage/**

Checks:

* Index-only.
* Never signs.
* Never gates acceptance.
* Never affects unlock predicates.
* TLS SPKI pinning where configured.
* Stores and serves bytes only.
* Does not validate DSM protocol correctness beyond structural malformed-object rejection where explicitly allowed.

CI and Scans

Files:

* scripts/codegen_enforce.sh
* scripts/ci_scan.sh
* Pipeline YAMLs.
* Makefile

Checks:

* Fail on version drift.
* Fail on protocol wall-clock markers.
* Fail on JSON envelopes.
* Fail on alt routes.
* Fail on deprecated paths.
* Fail on hex/base64 misuse in Core.
* Fail on unaudited unsafe.
* Enforce reproducible builds.
* Enforce warnings-as-errors.

Tests and Goldens

Files:

* tests/**
* tests/golden/**

Checks:

* Cross-language encode/decode equality.
* Canonical byte equality.
* Fork rejection.
* Duplicate parent rejection.
* DBRW proofs.
* DLV proofs.
* dBTC withdrawal/refund invariants.
* No protocol time usage.
* No legacy path acceptance.
* No schema/codegen drift.

⸻

Pre-Change Guardrails

Run these before changing code.

rg -n --fixed-strings "Envelope v2" -g "!node_modules" .
rg -n --fixed-strings "version = 2" -g "!node_modules" .
rg -n --fixed-strings "peer_id" -g "!node_modules" .
rg -n 'JSON\.(stringify|parse).*(\"type\"|\"data\")' -g "!node_modules" .
rg -n 'deprecated send\(|sendDeprecated\(|altRoute' -g "!node_modules" .
TIME_API_PATTERN='Date\.now|new Date\(|setTimeout\(|setInterval\(|System\.currentTimeMillis|Instant\.now|SystemTime|chrono::Utc'
rg -n "$TIME_API_PATTERN" -g "!node_modules" .
TS_MARKER='time[_-]?stamp|timestamp|wall[_-]?clock|created[_-]?at|updated[_-]?at'
rg -n "$TS_MARKER" -g "!node_modules" .
rg -n 'hex::(encode|decode)|base64(::|\.)?(encode|decode)' core/src
rg -n '^ *unsafe \{' core/src
LEGACY_MARKER='TODO|FIXME|HACK|STUB|PLACEHOLDER|mock|dummy|unimplemented!|todo!|panic!|expect\('
rg -n "$LEGACY_MARKER" -g "!node_modules" .

Interpretation rules:

* If time API hits occur in approved BLE transport/runtime files, verify they remain operational only and do not alter protocol semantics.
* If diagnostic-only hex appears in UI/CLI/test output, verify it is not accepted back into Core/SDK and is not used in persisted schema, bridge payload, storage, or envelope fields.
* If any legacy marker appears in production code, remove it unless explicitly justified as non-production test scaffolding.
* Any banned hit in protocol semantics blocks the change.

⸻

Post-Change Correctness Proofs

Run these after changing code.

pnpm --filter dsm-wallet run proto:gen
git diff --exit-code
pnpm test:canonical
./gradlew :android:test
cargo test -p core
go test ./sdk/go/...
cargo test -p core fork_rejects_duplicate_parent
bash scripts/codegen_enforce.sh
bash scripts/ci_scan.sh

If any check cannot be run, state it plainly:

Unrun checks:
- <check>: <reason>

If any check fails, do not claim completion. Report the failure and fix the cause.

⸻

Ban List

The following are build-blocking unless explicitly scoped to an approved non-protocol diagnostic or test-only context.

Version Drift and Deprecated Protocol

* Envelope v2
* version = 2
* peer_id

JSON Envelope or Alternative Transport

* JSON.stringify
* JSON.parse
* "type":
* "data":
* deprecated send(
* sendDeprecated(
* altRoute

Time and Clocks

Banned in protocol semantics, schemas, receipts, storage, logs, metrics, commitments, ordering, and state transitions:

* Date.now
* new Date(
* setTimeout(
* setInterval(
* System.currentTimeMillis
* Instant.now
* SystemTime
* chrono::Utc
* timestamp
* time_stamp
* time-stamp
* wall_clock
* wall-clock
* created_at
* updated_at

Exception:

Approved BLE transport/runtime files may use time APIs for operational transport behavior only. Those values must not enter protocol state, storage, commitments, receipts, or ordering.

Encoding Misuse

Banned in Core, SDK, JNI, storage, bridge, schemas, persisted objects, and protocol paths:

* hex::encode
* hex::decode
* base64.encode
* base64.decode
* base64::encode
* base64::decode

Exception:

Base64 may be used only at explicit I/O boundaries to wrap whole protobuf blobs through string-only platform APIs. It must not represent individual fields and must not enter canonicalization.

Hex may exist only as display-only diagnostics in UI/CLI/test output and must never be parsed or accepted by Core/SDK APIs.

Unsafe

* unsafe {

Exception:

Only audited, fenced, minimal unsafe blocks with explicit comments and test coverage.

Production Placeholder Markers

Banned in production paths:

* TODO
* FIXME
* HACK
* STUB
* PLACEHOLDER
* mock
* dummy
* unimplemented!
* todo!
* panic!
* unchecked expect(

⸻

Standing Rules

* Every change must cite exact artifacts.
* Every change must include pre-change and post-change guardrails.
* Every change must verify schema, codegen, bridge, and test alignment.
* Every replacement must remove the replaced legacy path in the same change.
* Envelope v3 is locked.
* Tag 2 remains reserved.
* JSON policy is unchanged: do not add JSON usage or widen JSON exceptions.
* Bytes inside.
* Protobuf Envelope v3 only.
* Base32 Crockford for copy/pasteable human-facing strings.
* Base64 only for whole-protobuf transport through string-only platform APIs.
* Hex never re-enters logic.
* Rust is the protocol authority.
* Kotlin transports.
* TypeScript renders.
* Storage nodes index only.
* DSM remains deterministic, clockless, binary-first, and strict-fail.

