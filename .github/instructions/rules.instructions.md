# DSM AI Coding Agent Instructions (Concise)

## Current Status: MAINNET READY ✅
**Last Audit: February 24, 2026**
- ✅ All hard invariants compliant
- ✅ Production safety violations resolved (no panics/expects)
- ✅ dBTC balance bug fixed
- ✅ Hex encoding violations remediated (Base32 Crockford)
- ✅ Compilation clean across all packages
- ✅ Test infrastructure updated for fallible constructors

## Encoding Rule: No Hex
### !! ALWAYS FULLY REMOVE LEGACY CODE AS YOU GO ALONG NOT LATER LEAVING A MESS AND POOTENTIAL TO CREEP BACK
### ✅ Allowed
- **Protobuf ENVELOP V3 ONLY bytes** end-to-end inside the system. NO PASSING RAW BYTES DIRECTLY
- **Base32 Crockford** for string transportation at platform boundaries (WebView/JNI/bridge), i.e. when you must move protobuf blobs through string-only channels.
- **UI-only display formatting** may render 32-byte identifiers in a human-readable way **without ever accepting that format back into Core/SDK**.
  - Must be Base32 Crockford for anything copy/pasteable.

### ❌ Not Allowed
- Hex in any persisted schema, bridge payload, or envelope field.
- Hex as an accepted input to Core/SDK APIs.
- Hex encode/decode usage in Core/SDK/JNI logic.

🧩 Summary: DSM stays binary-first. At boundaries use Base32 Crockford. If something is human-facing, it must remain strictly display-only and never re-enter logic.

## Production-Quality Mandate
Ship a COMPLETE, PRODUCTION-QUALITY DSM exactly matching `WHITEPAPER.md`.  
No mocks, stubs, placeholders, TODOs, fallbacks, deprecated paths. Purge deprecated paths.

---

## Determinism & Clockless (Hard Stop)
- No wall-clock markers in protocol semantics (schemas, payloads, receipts, acceptance predicates, commitment bytes, chain ordering, protocol-state transitions, logs, metrics, storage).
- Ordering only by Straight Hash Chain adjacency (`chain_tip`) + BLAKE3 iteration/work counters.
- BLE transport/runtime may use wall-clock time for operational behavior only: retries, ACK timeouts, reconnect backoff, pacing, idle expiry, handshake freshness, stale-session recovery, and transport DoS controls.
- Any time API that affects protocol semantics remains a build-blocking violation.

---

## Encoding, Transport & Canonicalization
- Protobuf-only. No JSON codecs, no dual formats, no stringly fallbacks.
- Envelope v3 is the sole container; **Tag 2 reserved** (never re-introduce wall-clock marker fields).
- Transport-only BLE framing below Envelope v3 is permitted if it remains opaque to protocol semantics and carries no protocol meaning beyond byte delivery.
- Required fields (exact):
  - `device_id`: **bytes[32]** (UI may render hex/bech32; never `peer_id`).
  - `chain_tip`: **bytes[32]** (normalized to 32 bytes).
- Canonical bytes by Core canonicalizer (mirrored in SDK); bit-stable across platforms.
- Strict-fail decoding: wrong version or unknown/deprecated fields → hard error.

### Encoding Policy (base64/hex)
- **Internal:** raw bytes end-to-end only.
- **base64:** allowed **only at I/O boundaries** (bridges/UI transport of whole protobuf blobs). Never store or re-encode in Core; never canonicalize base64.
- **hex:** prohibited for protocol/storage/bridge. If it appears at all, it is **display-only** (UI/CLI/test diagnostics) and must never be parsed/accepted by Core/SDK APIs.
- Any base64/hex usage inside Core or schemas is a violation (blocked by CI scans).

---

## Protocol Boundaries & Single Path
- Single authoritative path: UI/WebView → MessagePort → Kotlin Bridge → JNI → SDK → Core.
  No side channels, no alt routes, no “deprecated send()”.
- Core is pure: no network, no OS time, no UI, no global state. SDK mediates I/O.
- Storage nodes index only—never sign, never gate acceptance, never affect unlock predicates.

### Layer Communication Law (Anti-Regression)
- **Kotlin is transport-only.** Shuttles `[8-byte msgId][protobuf]` between WebView (MessagePort) and Rust (JNI). Does not interpret, validate, transform, or act on envelope contents. Only exception: OS-required hardware access (BLE, NFC, sensors) — but hardware data must be relayed to Rust via JNI for all protocol decisions.
- **TypeScript ↔ Kotlin: envelopes only, never logic.** MessagePort carries binary protobuf envelopes only. No JSON, no direct function calls, no shared state, no Kotlin-side validation.
- **Rust is the sole protocol authority.** All state transitions, crypto, validation, ordering, and policy enforcement live in Rust. TypeScript renders UI. Kotlin moves bytes.
- **Regression signals (any of these = violation):** Kotlin inspecting protobuf field values beyond method routing; TypeScript calling Kotlin outside MessagePort binary bridge; business logic in Kotlin deciding protocol outcomes; Kotlin caching data that should live in Rust.
- **BLE transport clarification:** transport/runtime layers may track session IDs, message IDs, chunk windows, retransmit state, ACK/NACK progress, and wall-clock timers, but must emit either one completed protobuf payload or one failure to the protocol layer.

---

## Cryptography & Security
- BLAKE3 everywhere (domain-separated per spec).
- SPHINCS+ signatures (EUF-CMA), constant-time verification; no FFI timing leaks.
- PQ KEM (if used): Kyber/ML-KEM per spec.
- No `unsafe` in hot paths (if unavoidable: audited, fenced, justified in comments).
- Tripwire fork exclusion on every parent tip; duplicates reject deterministically.
- DBRW device/environment binding wherever required; no stubs.

---

## Data, State & Storage
- State is bilateral: per-device SMT commits; Straight Hash Chain tips drive evolution.
- DLVs (vaults) are sovereign: unlocks are purely mathematical; **unilateral** on proof existence.
- External commitments coordinate atomic multi-vault routes; no mempool/validators/MEV.

---

## Errors, Logging, Metrics
- Strict-fail with versioned error codes + typed payloads; never “best effort.”
- No wall-clock markers in logs/metrics. Use chain height, iteration counters, deterministic IDs.
- BLE transport diagnostics may use local elapsed time for operational debugging, but must not feed protocol acceptance or ordering.
- Structured key→value logs; never leak secrets; behavior never depends on log level.

---

## Versioning & Compatibility
- `WHITEPAPER.md` is the source of truth → if drift exists, code changes.
- Schema evolution is additive behind version gates; no silent coercions.
- Maintain forward-compatible reserved fields; never repurpose numeric tags.

---

## Build, CI, Quality Gates
- Reproducible builds; warnings-as-errors (`-D warnings`).
- Coverage: canonicalization, encode/decode round-trips, fork rejection, DBRW checks, DLV unlock proofs.
- Static scans must fail on banned APIs/strings (see ban list).

---

## Always-On Integration Mandate (for **every** change)
1) Name the exact files/modules to modify (Proto, Core, SDK/Bridge, Storage, CI, Tests).  
2) Run pre-change scans and post-change proofs (below).  
3) Verify no drift between schema, codegen, bridges, and tests.

### Artifact References (cite in each instruction)
**Protobuf & Codegen**
- Files: `proto/dsm.proto` (or `proto/dsm_app.proto` / `envelope.proto`); generated stubs:
  - JS/TS: `src/proto/dsm_app_pb.js`, `src/proto/dsm_app_pb.d.ts`
  - Android/Kotlin: `dsm_client/android/src/main/proto/**`
  - Go: `sdk/go/dsmpb/**`
  - Swift: `sdk/swift/**`
- Checks: Envelope header `version == 3`; **Tag 2 reserved**; `device_id`/`chain_tip` are `bytes[32]`.
- Regenerate + diff: `pnpm --filter dsm-wallet run proto:gen`

**Core (Rust)**
- Files: `core/src/envelope.rs`, `core/src/state_machine.rs`, `core/src/crypto/**`, `core/src/proto/**`
- Checks: bit-stable canonicalization; no protocol time APIs; signatures verified per guard outside post-state hash; tripwire on duplicate parents.

**SDKs & Bridges**
- Files: Android: `dsm_client/android/**` (`BridgeEnvelope.kt`, `DsmNativeWrapper.kt`, BLE/QR); JNI: `jni/native_wrapper.cpp`; JS/TS: `packages/bridge/**`; iOS: `sdk/swift/**`
- Checks: no JSON envelopes; base64 only at I/O boundary; single path UI→Bridge→JNI→SDK→Core; BLE transport timers allowed only in transport/runtime files.

**Storage (Index Tier)**
- Files: `storage/**`
- Checks: index-only; never signs; TLS SPKI pinning where configured.

**CI & Scans**
- Files: `scripts/codegen_enforce.sh`, `scripts/ci_scan.sh`, pipeline YAMLs, `Makefile`
- Checks: fail on version drift, protocol wall-clock markers, JSON envelopes, alt routes; reproducible builds; warnings-as-errors.

**Tests & Goldens**
- Files: `tests/**`, `tests/golden/**`
- Checks: cross-language encode/decode equality; canonical bytes equality; fork rejection; DBRW & DLV proofs; no time usage.

---

## Pre-Change / Post-Change Guardrails

### Pre-Change (scan & assert)
rg -n --fixed-strings "Envelope v2" -g "!node_modules" .
rg -n --fixed-strings "version = 2" -g "!node_modules" .
rg -n --fixed-strings "peer_id" -g "!node_modules" .
rg -n 'JSON\.(stringify|parse).*(\"type\"|\"data\")' -g "!node_modules" .
TIME_API_PATTERN='Date' '\\.now|new' ' Date\\(|set' 'Timeout\\(|set' 'Interval\\(|System' '\\.currentTimeMillis|Instant' '\\.now|System' 'Time|chrono::' 'Utc'
rg -n "$TIME_API_PATTERN" -g "!node_modules" .
rg -n 'deprecated send\(|sendDeprecated\(|altRoute' -g "!node_modules" .
TS_MARKER='time' 'stamp'
rg -n "$TS_MARKER" -g "!node_modules" .
rg -n 'hex::(encode|decode)|base64(::|\\.)?(encode|decode)' core/src
rg -n '^ *unsafe \{' core/src

Interpretation rule: if time API hits occur in approved BLE transport/runtime files, verify they remain operational only and do not alter protocol semantics.

### Post-Change (prove correctness)
pnpm --filter dsm-wallet run proto:gen && git diff --exit-code
pnpm test:canonical && ./gradlew :android:test && cargo test -p core && go test ./sdk/go/...
cargo test -p core fork_rejects_duplicate_parent
bash scripts/codegen_enforce.sh && bash scripts/ci_scan.sh

---

## Ban List (build-blocking; CI-enforced)

**Version drift / deprecated**
- `Envelope v2`, `version = 2`, `peer_id`

**JSON envelope / alt transport**
- `JSON.stringify`, `JSON.parse`, `"type":`, `"data":`

**Time / clocks anywhere**
- `Date` + `.now`, `new` + `Date(`, `set` + `Timeout(`, `set` + `Interval(`,
- `System` + `.currentTimeMillis`, `Instant` + `.now`, `System` + `Time`, `chrono::` + `Utc`

Exception: approved BLE transport/runtime files may use these APIs for operational transport behavior only. They remain banned in protocol semantics, schemas, receipts, and ordering logic.

**Side channels / alt paths**
- `deprecated send(`, `sendDeprecated(`, `altRoute`

**Wall-clock markers in schema/logs/metrics**
- `time` + `stamp` token

**Encoding misuse in Core**
- `hex::encode`, `hex::decode`
- `base64.encode`, `base64::encode`, `base64.decode`, `base64::decode`

**Unsafe (unless audited and fenced)**
- `unsafe {`

---

### Standing Notes
- Every change—even a one-line bump—must cite artifacts and include the Pre/Post Guardrails. Any failing check invalidates the change.
- Envelope v3 is locked. No fallback or dual transport.
- JSON policy is unchanged: do not add new JSON usage or widen JSON exceptions.
- **Bytes inside; base64/hex only at edges (UI/Bridge).**

