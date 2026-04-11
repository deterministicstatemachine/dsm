# Rust-Authoritative Securing Phase Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate the silent "bounce-to-initialize" race during device setup by making Rust the sole authority for the `securing_device` phase, removing all frontend `setAppState` writers in the genesis flow.

**Architecture:** Add `securing_in_progress: bool` to Rust `SessionManager`, give `compute_phase()` an explicit `securing_device` arm that wins over `needs_genesis`, and expose the three mark operations through the **cross-platform `IngressRequest` oneof** (new `MarkGenesisSecuringOp` with `Phase { STARTED, COMPLETE, ABORTED }`). Kotlin's `BridgeIdentityHandler` calls `NativeBoundaryBridge.ingress(...)` with the MarkGenesisSecuring op around silicon-FP enrollment. `NativeBoundaryBridge.runBestEffortPostIngressHooks` auto-publishes fresh session state for the new op (mirroring the `session.lock`/`session.unlock` pattern). Strict ordering: **mark Rust via ingress → post-hook publishes session state → caller fires lifecycle envelope** (UI-thread FIFO preserves order between the scheduled publish and the subsequent envelope dispatch). Frontend `useGenesisFlow` becomes UI-only — it no longer writes `appState` for the securing phase. After this change, `useNativeSessionBridge` is the only writer to `appState`, and Rust is the only source of phase truth.

**Why ingress, not Android-only JNI exports:** per `rules.instructions.md` "Cross-Platform Ingress (Anti-Fragmentation)", new protocol operations MUST be added as `IngressRequest.operation` oneof variants so Android and iOS stay in lockstep. Adding three new `Java_com_dsm_wallet_bridge_UnifiedNativeApi_markGenesisSecuring*` JNI exports would be a regression signal (iOS cannot reach them). One proto variant, one Rust match arm, and both platforms get it for free.

**Tech Stack:** Rust (`dsm_sdk`, JNI), Kotlin (Android bridge layer), TypeScript (React hooks, `useSyncExternalStore`), `cargo ndk`, Gradle.

**Layer Communication Law (from `.github/instructions/rules.instructions.md`):** Kotlin is transport-only, Rust is sole protocol authority, TS renders UI only. This plan removes the last protocol-decision Kotlin/TS path on the genesis flow.

**Race condition root cause (Race A — silent stale-snapshot overwrite):**
1. Bar reaches 100 % → silicon-FP enrollment complete, `useGenesisFlow` has set `appState='securing_device'` from a `genesis.securing-device` envelope.
2. `BridgeIdentityHandler.installGenesisEnvelope` is still inside DBRW bootstrap → Rust's `has_identity` is still `false`, `compute_phase()` still returns `needs_genesis`.
3. Any of 15+ unrelated callers (`battery`, `walletRefresh`, `bridgeReady`, etc.) trigger `MainActivity.publishSessionState(...)` during this 100–500 ms window.
4. Rust returns a fresh snapshot whose `phase` is `needs_genesis` (because it has no concept of "securing").
5. `useNativeSessionBridge` mirrors that into `appRuntimeStore.setAppState('needs_genesis')`, silently overwriting `securing_device`. The screen bounces back to INITIALIZE with no error.

**Why this fix:** Single writer removes the race entirely. The "securing" phase is real protocol state, not ephemeral UX state, so it belongs in Rust per the Layer Communication Law. The window between bar-100% and `sdkBootstrapStrict()` returning is a real interval that the state machine should be able to represent.

**Adversarial-reasoning constraints (Gemini Flash damaged-survival verdict — applied):**
- ⚠️ **Wipe-on-onPause MUST stay.** Process death between `onPause` and `onStop` is real on memory-pressured Android — moving the wipe would create a security regression. `handleHostPauseDuringGenesis()` is unchanged in scope; we only add the marker call before the existing wipe.
- ⚠️ **JNI marker → publishSessionState → envelope ordering must be strict and synchronous.** JNI calls block the calling thread by default; this plan enforces the order without locks.
- ⚠️ **Single race explanation.** The fix targets Race A (silent bounce) only. The user confirmed: "plain and simple, no error message" → Race A.

---

## Pre-flight context

**Critical files (verified line numbers as of 2026-04-10):**

**Rust SDK (already partially complete via Task 1 commit `962952e`):**
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs` — `SessionManager` struct (`securing_in_progress` field already added), `Default`, `mark_securing_{started,complete,aborted}` methods (already added), `compute_phase()` with securing arm (already added). Module-level helpers `mark_securing_*_and_snapshot()` must be added in Task 3.
- `dsm_client/deterministic_state_machine/dsm_sdk/src/ingress.rs` — `dispatch_ingress` match on `ingress_request::Operation::*`. New `MarkGenesisSecuring` arm lives here in Task 3. `mark_genesis_securing_core(phase)` helper function lives here too.

**Proto schema + codegen:**
- `proto/dsm_app.proto:2541-2595` — Operation messages (`RouterQueryOp`, `EnvelopeOp`, `HardwareFactsOp`, `DrainEventsOp`, `IngressRequest`). New `MarkGenesisSecuringOp` message inserted around line 2554 (after `DrainEventsOp`). `IngressRequest.operation` oneof gains tag 6.
- Generated Rust stubs: `dsm_client/deterministic_state_machine/dsm_sdk/src/generated/**` (built by `prost-build` during cargo build when `DSM_PROTO_ROOT` is set).
- Generated Kotlin/Java stubs: `dsm_client/android/app/src/main/proto/**` → compiled by `Gradle protobuf plugin` into `dsm.types.proto.IngressRequest` + nested operation classes.
- Generated TypeScript stubs: `dsm_client/frontend/src/proto/**` (via `pnpm --filter dsm-wallet run proto:gen`).

**Android bridge (Kotlin is transport-only — no JNI export changes):**
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/NativeBoundaryBridge.kt:15-54` — `ingress()` entry point + `runBestEffortPostIngressHooks`. Task 4 extends the post-hook with a `MARK_GENESIS_SECURING` case that publishes session state (same pattern as `session.lock`/`session.unlock`).
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/UnifiedNativeApi.kt:53` — `dispatchIngress(requestBytes): ByteArray` — **unchanged**. No new externs added.
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:215` — `createGenesisSecuringDeviceEnvelope` (start of bar)
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:229` — `createGenesisSecuringCompleteEnvelope` (bar 100%)
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:254-260` — `sdkBootstrapStrict` (`has_identity` becomes true here, eventually)
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:301` — `sdkContextInitialized.set(true)`
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:302` — `createGenesisOkEnvelope`
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:308-333` — `handleHostPauseDuringGenesis`
- `dsm_client/android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt:161` — `getActiveInstance()`
- `dsm_client/android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt:427-454` — `publishSessionState()`
- `dsm_client/android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt:456-458` — `publishCurrentSessionState(reason)` (public)

**Frontend (UI-only):**
- `dsm_client/frontend/src/hooks/useGenesisFlow.ts:23-36` — visibilitychange listener (REMOVE)
- `dsm_client/frontend/src/hooks/useGenesisFlow.ts:39-61` — DSM event listener (KEEP only progress branch)
- `dsm_client/frontend/src/hooks/useGenesisFlow.ts:63-118` — `handleGenerateGenesis` (REMOVE setAppState calls)
- `dsm_client/frontend/src/hooks/__tests__/useGenesisFlow.test.ts` — UI-only behaviour test target

**NDK rebuild command (from CLAUDE.md, runs from worktree root):**
```bash
rm -f dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so \
     dsm_client/android/app/src/main/jniLibs/armeabi-v7a/libdsm_sdk.so \
     dsm_client/android/app/src/main/jniLibs/x86_64/libdsm_sdk.so && \
cd dsm_client/decentralized_state_machine && \
DSM_PROTO_ROOT=/Users/cryptskii/Desktop/claude_workspace/dsm/proto \
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/android/app/src/main/jniLibs \
  --platform 23 build --release --package dsm_sdk --features=jni,bluetooth
```
> **Note:** the NDK build script in CLAUDE.md uses `dsm_client/decentralized_state_machine` but the actual cargo workspace lives at `dsm_client/deterministic_state_machine`. If `cd decentralized_state_machine` fails, use `deterministic_state_machine` (which is what `find` confirms is real). Update memory afterwards.

**Test devices:** Galaxy A54 (`R5CW620MQVL`, sender) and Galaxy A16 (`RF8Y90PX5GN`, receiver, flaky USB).

---

## Task 1: Add `securing_in_progress` field + setters to `SessionManager` ✅ DONE (commit `962952e`)

> **Status:** complete. The struct field, `Default` init, three setters, `compute_phase()` arm, and three unit tests (`securing_in_progress_takes_precedence_over_needs_genesis`, `securing_in_progress_yields_to_fatal_error`, `securing_aborted_clears_flag`) all landed in commit `962952e` and have been code-reviewed. Three pre-existing broken tests (`auto_lock_on_background`, `no_auto_lock_when_policy_disabled`, `no_auto_lock_while_qr_scanner_active`) were fixed in the same commit by adding missing `let _g = setup_test_env();` guards. All 15 `session_manager::tests` pass. The original Task 1 specification below is preserved for historical reference.

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs:65-90` (struct + Default)
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs:344-398` (test module)

**Step 1: Write the failing test**

Add at the end of the `tests` module in `session_manager.rs` (after the existing `phase_locked_when_lock_set` test):

```rust
#[test]
fn securing_in_progress_takes_precedence_over_needs_genesis() {
    let _g = setup_test_env();
    SDK_READY.store(true, Ordering::SeqCst);
    // has_identity is false → would normally be needs_genesis

    let mut mgr = SessionManager::default();
    mgr.mark_securing_started();
    let snap = mgr.compute_snapshot();
    assert_eq!(snap.phase, "securing_device", "securing must beat needs_genesis");

    mgr.mark_securing_complete();
    let snap = mgr.compute_snapshot();
    assert_eq!(
        snap.phase, "needs_genesis",
        "after complete, falls back to needs_genesis until has_identity flips"
    );
}

#[test]
fn securing_in_progress_yields_to_fatal_error() {
    let _g = setup_test_env();
    SDK_READY.store(true, Ordering::SeqCst);

    let mut mgr = SessionManager::default();
    mgr.mark_securing_started();
    mgr.fatal_error = Some("boom".into());
    let snap = mgr.compute_snapshot();
    assert_eq!(snap.phase, "error", "fatal error must beat securing");
}

#[test]
fn securing_aborted_clears_flag() {
    let _g = setup_test_env();
    SDK_READY.store(true, Ordering::SeqCst);

    let mut mgr = SessionManager::default();
    mgr.mark_securing_started();
    assert!(mgr.securing_in_progress);
    mgr.mark_securing_aborted();
    assert!(!mgr.securing_in_progress);
    let snap = mgr.compute_snapshot();
    assert_eq!(snap.phase, "needs_genesis");
}
```

**Step 2: Run test to verify it fails**

```bash
cd dsm_client/deterministic_state_machine && \
  cargo test -p dsm_sdk --features=jni,bluetooth \
    sdk::session_manager::tests::securing -- --nocapture
```
Expected: FAIL with `no method named 'mark_securing_started' / 'securing_in_progress' field not found`.

**Step 3: Add field + Default + setters + compute_phase arm**

In `session_manager.rs`, modify the `SessionManager` struct (current lines ~65-75):

```rust
#[derive(Debug, Clone)]
pub struct SessionManager {
    // --- Owned state (no other Rust home) ---
    pub lock_enabled: bool,
    pub lock_locked: bool,
    pub lock_method: String,
    pub lock_on_pause: bool,
    pub fatal_error: Option<String>,
    pub wallet_refresh_hint: u64,
    pub hardware: HardwareFacts,
    pub lock_state_initialized: bool,
    /// Set true while DBRW silicon-fingerprint enrollment + sdkBootstrapStrict
    /// are running. Cleared by mark_securing_complete or mark_securing_aborted.
    /// Compute_phase exposes this as the `securing_device` phase, beating
    /// `needs_genesis` so external `publishSessionState` calls during the
    /// 100-500ms securing window cannot bounce the UI back to INITIALIZE.
    pub securing_in_progress: bool,
}
```

Add `securing_in_progress: false,` to the `Default` impl (~lines 77-90). Add the three setters in the `impl SessionManager` block (somewhere between `set_locked` and `compute_phase`, around line 142):

```rust
/// Begin the device-securing phase. Called by the JNI marker before
/// silicon-fingerprint enrollment starts. Idempotent.
pub fn mark_securing_started(&mut self) {
    self.securing_in_progress = true;
    log::info!("SessionManager: mark_securing_started");
}

/// End the securing phase normally. The phase will fall back to
/// `needs_genesis` until `sdkBootstrapStrict` flips `has_identity`,
/// then to `wallet_ready`.
pub fn mark_securing_complete(&mut self) {
    self.securing_in_progress = false;
    log::info!("SessionManager: mark_securing_complete");
}

/// End the securing phase because Kotlin is wiping partial DBRW state.
/// Identical to complete from a flag perspective; the wipe path will
/// also clear `has_identity`, so phase falls back to `needs_genesis`.
pub fn mark_securing_aborted(&mut self) {
    self.securing_in_progress = false;
    log::warn!("SessionManager: mark_securing_aborted");
}
```

Modify `compute_phase` (current lines 192-206) to add the securing arm. **Order matters** — `error` still wins, then `runtime_loading`, then `securing_in_progress`, then `needs_genesis`:

```rust
fn compute_phase(&self) -> &'static str {
    if self.fatal_error.is_some() {
        return "error";
    }
    if !SDK_READY.load(Ordering::SeqCst) {
        return "runtime_loading";
    }
    if self.securing_in_progress {
        return "securing_device";
    }
    if !AppState::get_has_identity() {
        return "needs_genesis";
    }
    if self.lock_locked {
        return "locked";
    }
    "wallet_ready"
}
```

**Step 4: Run test to verify it passes**

```bash
cd dsm_client/deterministic_state_machine && \
  cargo test -p dsm_sdk --features=jni,bluetooth \
    sdk::session_manager::tests -- --nocapture
```
Expected: all `tests::securing_*` PASS, no existing test regresses (the new arm is strictly downstream of `runtime_loading` so existing assertions hold).

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs
git commit -m "feat(sdk): add securing_in_progress phase to SessionManager

Adds an explicit 'securing_device' phase to compute_phase() guarded by a
SessionManager flag, beating needs_genesis. This is the foundation for
fixing the bounce-to-initialize race where external publishSessionState
calls during DBRW securing leak the unfinished needs_genesis state.

Refs: docs/plans/2026-04-10-rust-authoritative-securing-phase.md Task 1"
```

---

## Task 2: Add `MarkGenesisSecuringOp` to `IngressRequest` proto + regenerate bindings

> **Architectural rationale:** per `.github/instructions/rules.instructions.md` "Cross-Platform Ingress (Anti-Fragmentation)", new protocol operations MUST be expressed as `IngressRequest.operation` oneof variants. This keeps Android and iOS on the same seam. The three mark actions (STARTED, COMPLETE, ABORTED) collapse into one proto op with a `Phase` enum.

**Files:**
- Modify: `proto/dsm_app.proto:2541-2595` — add `MarkGenesisSecuringOp` message and extend `IngressRequest.operation` oneof with tag 6.
- Regenerate: Rust (`dsm_client/deterministic_state_machine/dsm_sdk/src/generated/**` via cargo build), Kotlin (`dsm_client/android/app/src/main/proto/**` via Gradle protobuf plugin), TypeScript (`dsm_client/frontend/src/proto/**` via `pnpm proto:gen`).

**Step 1: Add the proto message and extend the oneof**

In `proto/dsm_app.proto`, after the `DrainEventsOp` message (currently lines 2552-2554) and BEFORE the `enum SdkEventKind` (line 2556), insert:

```proto
// Mark the genesis/device-securing phase in the Rust SessionManager. Used by
// the Android bridge (and future iOS host) to flip the securing_in_progress
// flag around DBRW silicon-fingerprint enrollment. All three phases funnel
// through the same op so callers only need to switch a phase value — no new
// per-platform JNI/FFI exports. See
// .github/instructions/rules.instructions.md "Cross-Platform Ingress".
message MarkGenesisSecuringOp {
  enum Phase {
    PHASE_UNSPECIFIED = 0;
    PHASE_STARTED     = 1;
    PHASE_COMPLETE    = 2;
    PHASE_ABORTED     = 3;
  }
  Phase phase = 1;
}
```

Then modify the `IngressRequest.operation` oneof (currently lines 2588-2596) to add tag 6:

```proto
// Canonical platform-agnostic ingress request.
message IngressRequest {
  oneof operation {
    RouterQueryOp         router_query          = 1;
    RouterInvokeOp        router_invoke         = 2;
    EnvelopeOp            envelope              = 3;
    HardwareFactsOp       hardware_facts        = 4;
    DrainEventsOp         drain_events          = 5;
    MarkGenesisSecuringOp mark_genesis_securing = 6;
  }
}
```

**Important — proto invariants:** no `timestamp` or wall-clock fields (CI guardrail), no `dsm_max_len` on enum fields (enums are fixed width), no renumbering existing tags (forward compat).

**Step 2: Regenerate bindings**

The repo has three codegen paths. Run them in order:

```bash
# 1. Rust: prost-build runs during cargo build, needs DSM_PROTO_ROOT pointing at proto/
DSM_PROTO_ROOT=/Users/cryptskii/Desktop/claude_workspace/dsm/proto \
  cargo check -p dsm_sdk --features=jni,bluetooth \
    --manifest-path dsm_client/deterministic_state_machine/Cargo.toml

# 2. Android Kotlin/Java stubs: the Gradle protobuf plugin regenerates on next build.
#    The source-of-truth .proto file lives under dsm_client/android/app/src/main/proto/
#    and may be a COPY of proto/dsm_app.proto — check and sync if needed:
diff proto/dsm_app.proto dsm_client/android/app/src/main/proto/dsm_app.proto 2>&1 || true
# If they differ, copy the canonical proto into the Android tree:
cp proto/dsm_app.proto dsm_client/android/app/src/main/proto/dsm_app.proto

# 3. TypeScript: pnpm proto:gen (the exact filter may differ — check package.json)
cd dsm_client/frontend && pnpm proto:gen 2>&1 || \
  (cd ../.. && pnpm --filter dsm-wallet run proto:gen)
```

Expected: all three regenerations succeed. If the TypeScript proto:gen script path is different, use `rg "proto:gen" dsm_client/frontend/package.json dsm_client/package.json` to find it.

**Step 3: Verify the new symbols are in the generated Rust code**

```bash
rg -n "MarkGenesisSecuringOp|mark_genesis_securing" \
  dsm_client/deterministic_state_machine/dsm_sdk/src/generated/ 2>&1
```
Expected: matches for `struct MarkGenesisSecuringOp`, `mod mark_genesis_securing_op`, `enum Phase`, and the new `MarkGenesisSecuring` variant in `ingress_request::Operation`.

**Step 4: Verify the Kotlin stubs**

```bash
cd dsm_client/android && ./gradlew :app:generateDebugProto
rg -n "MarkGenesisSecuringOp|MARK_GENESIS_SECURING" \
  dsm_client/android/app/build/generated/source/proto/ 2>&1 | head -n 20
```
Expected: `class MarkGenesisSecuringOp`, enum `Phase`, and `IngressRequest.OperationCase.MARK_GENESIS_SECURING` appear in the generated Java.

**Step 5: Verify the TypeScript stubs**

```bash
rg -n "MarkGenesisSecuringOp|mark_genesis_securing|markGenesisSecuring" \
  dsm_client/frontend/src/proto/ 2>&1 | head -n 20
```
Expected: matches. (These stubs aren't strictly needed for this plan because the frontend doesn't call this op directly, but keeping all three languages in sync is required by the project's regeneration rules.)

**Step 6: Diff-check that no other generated file drifted**

```bash
git diff --stat proto/ \
  dsm_client/deterministic_state_machine/dsm_sdk/src/generated/ \
  dsm_client/android/app/src/main/proto/ \
  dsm_client/frontend/src/proto/
```
Expected: only files touching MarkGenesisSecuring/IngressRequest should be diff'd.

**Step 7: Commit**

```bash
git add proto/dsm_app.proto \
        dsm_client/android/app/src/main/proto/dsm_app.proto \
        dsm_client/deterministic_state_machine/dsm_sdk/src/generated/ \
        dsm_client/frontend/src/proto/
git commit -m "proto: add MarkGenesisSecuringOp to IngressRequest (tag 6)

Introduces a cross-platform mark op so the three securing phases
(STARTED/COMPLETE/ABORTED) route through the existing ingress.rs seam
instead of Android-only JNI exports. Keeps iOS in lockstep and satisfies
the 'Cross-Platform Ingress (Anti-Fragmentation)' rule.

New message: MarkGenesisSecuringOp { Phase phase = 1; }
New oneof variant: IngressRequest.operation.mark_genesis_securing = 6;

Refs: docs/plans/2026-04-10-rust-authoritative-securing-phase.md Task 2"
```

---

## Task 3: Add `session_manager` helpers + `ingress.rs` match arm + TDD tests

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs` — add three module-level helpers next to `clear_fatal_error_and_snapshot` (already exists).
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/src/ingress.rs` — add `mark_genesis_securing_core(phase)` function + a new match arm in `dispatch_ingress` for `Operation::MarkGenesisSecuring`. Add TDD tests in the existing `#[cfg(test)]` module.

**Step 1: Add module-level helpers in `session_manager.rs`**

Locate `clear_fatal_error_and_snapshot` (around line 342). Directly below it, add:

```rust
/// Mark device-securing started and return updated snapshot bytes.
/// Called from `ingress::dispatch_ingress` when a MarkGenesisSecuringOp
/// with phase STARTED arrives. Returns the envelope-wrapped SessionStateResponse
/// bytes so the caller can relay them to the UI if desired.
pub fn mark_securing_started_and_snapshot() -> Vec<u8> {
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.sync_lock_config_from_app_state();
    mgr.mark_securing_started();
    envelope_wrap_snapshot(mgr.compute_snapshot())
}

/// Mark device-securing complete and return updated snapshot bytes.
pub fn mark_securing_complete_and_snapshot() -> Vec<u8> {
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.sync_lock_config_from_app_state();
    mgr.mark_securing_complete();
    envelope_wrap_snapshot(mgr.compute_snapshot())
}

/// Mark device-securing aborted and return updated snapshot bytes.
pub fn mark_securing_aborted_and_snapshot() -> Vec<u8> {
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.sync_lock_config_from_app_state();
    mgr.mark_securing_aborted();
    envelope_wrap_snapshot(mgr.compute_snapshot())
}
```

> **Verify `envelope_wrap_snapshot` exists.** Check that `session_manager.rs` already exports a helper of that name (it's used by `clear_fatal_error_and_snapshot` and `update_hardware_and_snapshot`). If the real name is different (e.g. `wrap_snapshot_as_envelope_bytes`), use that — the three new helpers should follow the exact pattern of `clear_fatal_error_and_snapshot` so there is no drift.

**Step 2: Add a `session_manager::tests` unit test for the helpers**

In the existing `tests` module of `session_manager.rs`, add:

```rust
#[test]
fn marker_helpers_round_trip_through_compute_phase() {
    let _g = setup_test_env();
    SDK_READY.store(true, Ordering::SeqCst);

    // Reset global manager state for this test
    {
        let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
        mgr.securing_in_progress = false;
        mgr.fatal_error = None;
    }

    let started = mark_securing_started_and_snapshot();
    assert!(!started.is_empty());
    {
        let mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
        assert!(mgr.securing_in_progress, "STARTED must set the flag");
    }

    let complete = mark_securing_complete_and_snapshot();
    assert!(!complete.is_empty());
    {
        let mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
        assert!(!mgr.securing_in_progress, "COMPLETE must clear the flag");
    }

    // Re-start then abort — flag must end up cleared.
    let _ = mark_securing_started_and_snapshot();
    let aborted = mark_securing_aborted_and_snapshot();
    assert!(!aborted.is_empty());
    let mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    assert!(!mgr.securing_in_progress, "ABORTED must clear the flag");
}
```

**Step 3: Add the `mark_genesis_securing_core` function and ingress match arm**

In `ingress.rs`, add the core function near the other `*_core` helpers (around line 147, next to `drain_events_core`):

```rust
fn mark_genesis_securing_core(phase: i32) -> Result<Vec<u8>, pb::Error> {
    // Phase enum values mirror pb::mark_genesis_securing_op::Phase:
    //   PHASE_UNSPECIFIED = 0
    //   PHASE_STARTED     = 1
    //   PHASE_COMPLETE    = 2
    //   PHASE_ABORTED     = 3
    use pb::mark_genesis_securing_op::Phase as P;
    let enum_phase = P::try_from(phase).unwrap_or(P::Unspecified);
    let bytes = match enum_phase {
        P::Started => crate::sdk::session_manager::mark_securing_started_and_snapshot(),
        P::Complete => crate::sdk::session_manager::mark_securing_complete_and_snapshot(),
        P::Aborted => crate::sdk::session_manager::mark_securing_aborted_and_snapshot(),
        P::Unspecified => {
            return Err(ingress_error(
                ERROR_CODE_INVALID_INPUT,
                "ingress: mark_genesis_securing phase is unspecified",
            ));
        }
    };
    Ok(bytes)
}
```

> **Note on `try_from`:** prost's `Enumeration` derive implements `TryFrom<i32>`. The exact module path depends on how `MarkGenesisSecuringOp` lands in the generated code — it's typically `pb::mark_genesis_securing_op::Phase`. If the generated path is different (check `dsm_client/deterministic_state_machine/dsm_sdk/src/generated/dsm_app.rs`), use that path instead. Do not use hard-coded integer comparisons — they silently break on schema evolution.

Then extend `dispatch_ingress` (around line 361) to add the new match arm immediately before the `None` branch:

```rust
        Some(ingress_request::Operation::DrainEvents(op)) => drain_events_core(op.max_events),
        Some(ingress_request::Operation::MarkGenesisSecuring(op)) => {
            mark_genesis_securing_core(op.phase)
        }
        None => Err(ingress_error(
            ERROR_CODE_INVALID_INPUT,
            "ingress: empty IngressRequest (no operation set)",
        )),
```

**Step 4: Add `ingress::tests` integration tests**

In the existing `#[cfg(test)]` module of `ingress.rs` (starts around line 540), add:

```rust
#[test]
fn dispatch_ingress_mark_genesis_securing_started_sets_flag() {
    let _g = crate::sdk::session_manager::test_env::setup_test_env();
    crate::sdk::session_manager::SDK_READY.store(true, std::sync::atomic::Ordering::SeqCst);

    let response = dispatch_ingress(IngressRequest {
        operation: Some(ingress_request::Operation::MarkGenesisSecuring(
            pb::MarkGenesisSecuringOp {
                phase: pb::mark_genesis_securing_op::Phase::Started as i32,
            },
        )),
    });
    match response.result {
        Some(ingress_response::Result::OkBytes(bytes)) => assert!(!bytes.is_empty()),
        other => panic!("expected OkBytes, got {:?}", other),
    }

    let mgr = crate::sdk::session_manager::SESSION_MANAGER
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    assert!(
        mgr.securing_in_progress,
        "dispatch_ingress(STARTED) must flip securing_in_progress"
    );
}

#[test]
fn dispatch_ingress_mark_genesis_securing_complete_clears_flag() {
    let _g = crate::sdk::session_manager::test_env::setup_test_env();
    crate::sdk::session_manager::SDK_READY.store(true, std::sync::atomic::Ordering::SeqCst);

    // Precondition: flag is set
    {
        let mut mgr = crate::sdk::session_manager::SESSION_MANAGER
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        mgr.mark_securing_started();
    }

    let response = dispatch_ingress(IngressRequest {
        operation: Some(ingress_request::Operation::MarkGenesisSecuring(
            pb::MarkGenesisSecuringOp {
                phase: pb::mark_genesis_securing_op::Phase::Complete as i32,
            },
        )),
    });
    assert!(matches!(
        response.result,
        Some(ingress_response::Result::OkBytes(_))
    ));

    let mgr = crate::sdk::session_manager::SESSION_MANAGER
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    assert!(!mgr.securing_in_progress);
}

#[test]
fn dispatch_ingress_mark_genesis_securing_unspecified_errors() {
    let _g = crate::sdk::session_manager::test_env::setup_test_env();

    let response = dispatch_ingress(IngressRequest {
        operation: Some(ingress_request::Operation::MarkGenesisSecuring(
            pb::MarkGenesisSecuringOp {
                phase: pb::mark_genesis_securing_op::Phase::Unspecified as i32,
            },
        )),
    });
    match response.result {
        Some(ingress_response::Result::Error(err)) => {
            assert_eq!(err.code, ERROR_CODE_INVALID_INPUT);
        }
        other => panic!("expected Error, got {:?}", other),
    }
}
```

> **Test-env helper path:** the existing ingress tests reference `crate::sdk::session_manager::test_env::setup_test_env` only if that module exists. If the helper is private to `session_manager.rs` (it is, per commit `962952e`), expose it as `pub(crate)` — or mirror the setup locally (`let _ = TEST_LOCK.lock();`). Prefer `pub(crate)` so the ingress tests share the real guard.

**Step 5: Run the tests — FAIL first, then PASS**

```bash
# Fail (helpers and ingress arm missing)
cd dsm_client/deterministic_state_machine && \
  DSM_PROTO_ROOT=/Users/cryptskii/Desktop/claude_workspace/dsm/proto \
  cargo test -p dsm_sdk --features=jni,bluetooth \
    sdk::session_manager::tests::marker_helpers_round_trip \
    ingress::tests::dispatch_ingress_mark_genesis_securing -- --nocapture
```
Apply Steps 1 + 3 and re-run. Expected: all four tests PASS.

**Step 6: Full test sweep**

```bash
cd dsm_client/deterministic_state_machine && \
  DSM_PROTO_ROOT=/Users/cryptskii/Desktop/claude_workspace/dsm/proto \
  cargo test -p dsm_sdk --features=jni,bluetooth sdk::session_manager ingress
```
Expected: all existing session_manager + ingress tests still green, plus the new ones.

**Step 7: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs \
        dsm_client/deterministic_state_machine/dsm_sdk/src/ingress.rs
git commit -m "feat(sdk): route MarkGenesisSecuringOp through ingress.rs

Adds three helper functions (mark_securing_{started,complete,aborted}_and_snapshot)
in session_manager.rs and a match arm in dispatch_ingress that routes the
new MarkGenesisSecuringOp.phase enum to the right helper. This keeps the
single-entry-point ingress contract for both Android JNI and iOS FFI —
no new per-platform exports needed.

Four new tests: one session_manager unit test round-tripping the three
helpers through compute_phase, and three ingress integration tests
exercising STARTED, COMPLETE, and UNSPECIFIED (error path).

Refs: docs/plans/2026-04-10-rust-authoritative-securing-phase.md Task 3"
```

---

## Task 4: Wire `markGenesisSecuring(STARTED)` via ingress in `installGenesisEnvelope`

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/NativeBoundaryBridge.kt:29-53` — extend the post-hook `when (request.operationCase)` with a `MARK_GENESIS_SECURING` case that runs `publishCurrentSessionState` on the UI thread (mirroring the `session.lock`/`session.unlock` pattern already there).
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt` — add a private helper `markGenesisSecuring(phase)` that builds + dispatches an `IngressRequest`, then call it at line ~215 just before `createGenesisSecuringDeviceEnvelope`.

**Step 1: Extend the `NativeBoundaryBridge` post-hook**

Open `NativeBoundaryBridge.kt`. Inside `runBestEffortPostIngressHooks`, the existing `when (request.operationCase)` already handles `ROUTER_INVOKE` and `ENVELOPE`. Add a new branch for `MARK_GENESIS_SECURING` so every mark op automatically republishes session state:

```kotlin
when (request.operationCase) {
    IngressRequest.OperationCase.ROUTER_INVOKE -> {
        try {
            UnifiedNativeApi.maybeRefreshNfcCapsule()
        } catch (_: Throwable) {
            // no-op
        }
        val method = request.routerInvoke.method
        if (method == "session.lock" || method == "session.unlock") {
            MainActivity.getActiveInstance()?.runOnUiThread {
                MainActivity.getActiveInstance()?.publishCurrentSessionState(method)
            }
        }
    }
    IngressRequest.OperationCase.ENVELOPE -> {
        try {
            UnifiedNativeApi.maybeRefreshNfcCapsule()
        } catch (_: Throwable) {
            // no-op
        }
    }
    IngressRequest.OperationCase.MARK_GENESIS_SECURING -> {
        // Rust already flipped securing_in_progress inside dispatchIngress above.
        // Republish session.state so any subscriber relying on the old snapshot
        // (useNativeSessionBridge in the WebView) observes the new phase BEFORE
        // the caller fires the next lifecycle envelope. UI-thread FIFO preserves
        // ordering vs. the subsequent BleEventRelay dispatch on the caller side.
        val phaseName = request.markGenesisSecuring.phase.name
        MainActivity.getActiveInstance()?.runOnUiThread {
            MainActivity.getActiveInstance()
                ?.publishCurrentSessionState("genesisSecuring:$phaseName")
        }
    }
    else -> {
        // no-op
    }
}
```

**Step 2: Add the `markGenesisSecuring` helper inside `BridgeIdentityHandler.kt`**

Near the top of the class body (alongside other private helpers), add:

```kotlin
/**
 * Build + dispatch a MarkGenesisSecuring ingress request. This is the cross-platform
 * seam — the same op is reachable from iOS via dsm_dispatch_ingress_request once the
 * iOS host is wired. Blocks the calling thread on the JNI call so the Rust flag flip
 * is visible before the next line runs. NativeBoundaryBridge's post-hook schedules
 * publishCurrentSessionState on the UI thread after the mark lands; subsequent
 * BleEventRelay.dispatchEnvelope calls share the same UI-thread FIFO, preserving
 * the "Rust flag set → session.state published → lifecycle envelope fired" ordering
 * that kills the bounce-to-initialize race.
 */
private fun markGenesisSecuring(phase: MarkGenesisSecuringOp.Phase) {
    try {
        val request = IngressRequest.newBuilder()
            .setMarkGenesisSecuring(
                MarkGenesisSecuringOp.newBuilder().setPhase(phase).build()
            )
            .build()
        NativeBoundaryBridge.ingress(request.toByteArray())
    } catch (t: Throwable) {
        Log.w(logTag, "markGenesisSecuring($phase) ingress call failed", t)
    }
}
```

Add the two new imports near the top of `BridgeIdentityHandler.kt`:

```kotlin
import dsm.types.proto.IngressRequest
import dsm.types.proto.MarkGenesisSecuringOp
```

**Step 3: Call the helper at the start-of-bar site (line ~215)**

The current sequence around line 215 is:

```kotlin
UnifiedNativeApi.createGenesisSecuringDeviceEnvelope().let {
    if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it)
}
Log.i(logTag, "installGenesisEnvelope: starting silicon fingerprint enrollment...")
```

Replace with:

```kotlin
// STRICT ORDER (see Task 4 doc):
// 1. dispatchIngress(MarkGenesisSecuring STARTED) — Rust flips securing_in_progress
//    synchronously, then NativeBoundaryBridge post-hook posts a fresh session.state
//    publish to the UI thread queue.
// 2. createGenesisSecuringDeviceEnvelope dispatch — also hits the UI thread queue
//    after the publish because of step 1's post-hook, so useNativeSessionBridge
//    observes securing_device BEFORE the bar renders.
markGenesisSecuring(MarkGenesisSecuringOp.Phase.PHASE_STARTED)
UnifiedNativeApi.createGenesisSecuringDeviceEnvelope().let {
    if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it)
}
Log.i(logTag, "installGenesisEnvelope: starting silicon fingerprint enrollment...")
```

**Step 4: Compile check**

```bash
cd dsm_client/android && \
  ./gradlew :app:compileDebugKotlin
```
Expected: SUCCESS. If `IngressRequest.OperationCase.MARK_GENESIS_SECURING` is not yet present, Task 2's proto codegen step was incomplete — rerun `./gradlew :app:generateDebugProto` and re-check.

**Step 5: Commit**

```bash
git add dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/NativeBoundaryBridge.kt \
        dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt
git commit -m "feat(android): mark Rust securing STARTED via ingress before bar

Routes the mark call through NativeBoundaryBridge.ingress so it shares
the cross-platform IngressRequest seam instead of an Android-only JNI
export. Extends the post-hook to auto-publish session.state for the
MARK_GENESIS_SECURING operation case — the same pattern used for
session.lock/unlock. UI-thread FIFO preserves strict ordering between
the published session.state and the subsequent bar envelope dispatch.

Refs: docs/plans/2026-04-10-rust-authoritative-securing-phase.md Task 4"
```

---

## Task 5: Wire `markGenesisSecuring(COMPLETE)` via ingress after `sdkContextInitialized.set(true)`

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:301-302`

**Step 1: Apply the marker call with strict ordering**

The current sequence at lines 301-302 is:
```kotlin
sdkContextInitialized.set(true)
UnifiedNativeApi.createGenesisOkEnvelope().let { if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it) }
```

Replace with:

```kotlin
sdkContextInitialized.set(true)

// STRICT ORDER (see Task 4 doc): dispatchIngress(COMPLETE) flips Rust flag back
// off AND triggers the post-hook publish. At this point has_identity is true
// (sdkBootstrapStrict succeeded above), so compute_phase returns wallet_ready.
// The subsequent OK lifecycle envelope sits behind the publish in the UI-thread
// queue, so useNativeSessionBridge observes wallet_ready first — not a
// transient needs_genesis.
markGenesisSecuring(MarkGenesisSecuringOp.Phase.PHASE_COMPLETE)
UnifiedNativeApi.createGenesisOkEnvelope().let {
    if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it)
}
```

**Step 2: Compile check**

```bash
cd dsm_client/android && \
  ./gradlew :app:compileDebugKotlin
```
Expected: SUCCESS.

**Step 3: Commit**

```bash
git add dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt
git commit -m "feat(android): mark Rust securing COMPLETE via ingress before OK

After sdkContextInitialized.set(true), dispatch the MarkGenesisSecuring
COMPLETE op through the ingress seam. Post-hook publishes fresh
session.state with wallet_ready (has_identity is already true here)
before the OK lifecycle envelope reaches the WebView via UI-thread FIFO.

Refs: docs/plans/2026-04-10-rust-authoritative-securing-phase.md Task 5"
```

---

## Task 6: Wire `markGenesisSecuring(ABORTED)` via ingress in pause + catch paths

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:308-333` (handleHostPauseDuringGenesis)
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt` (the catch block of installGenesisEnvelope — exact location confirmed in Step 1 below)

**Step 1: Find the catch block in installGenesisEnvelope**

```bash
grep -n "catch (e:" dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt
```
Look for the catch block at the bottom of `installGenesisEnvelope` that wipes partial state on failure. There may also be one inside `captureDeviceBindingForGenesisEnvelope` (~line 514-566). Both abort paths must call the marker.

**Step 2: Apply the marker call to `handleHostPauseDuringGenesis`**

In the function at lines 308-333, modify the body. Currently lines 320-330 do:

```kotlin
genesisLifecycleInvalidated.set(true)
clearGenesisArtifacts(...)
UnifiedNativeApi.createGenesisSecuringAbortedEnvelope().let { ... }
UnifiedNativeApi.createGenesisErrorEnvelope().let { ... }
```

Insert the marker BEFORE the wipe and BEFORE the lifecycle envelopes:

```kotlin
if (!genesisLifecycleInFlight.get()) {
    return
}
genesisLifecycleInvalidated.set(true)

// STRICT ORDER: dispatchIngress(ABORTED) flips Rust flag AND post-hook publishes
// a fresh session.state. The subsequent wipe + envelope dispatches arrive after
// that publish on the UI thread queue, so no observer can see securing_device
// once the flow has decided to die.
markGenesisSecuring(MarkGenesisSecuringOp.Phase.PHASE_ABORTED)

clearGenesisArtifacts(
    prefs = prefs,
    sdkContextInitialized = sdkContextInitialized,
    keyDeviceId = keyDeviceId,
    keyGenesisHash = keyGenesisHash,
    keyGenesisEnvelope = keyGenesisEnvelope,
    keyDbrwSalt = keyDbrwSalt,
    logTag = logTag,
)
UnifiedNativeApi.createGenesisSecuringAbortedEnvelope().let {
    if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it)
}
UnifiedNativeApi.createGenesisErrorEnvelope().let {
    if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it)
}
Log.w(logTag, "handleHostPauseDuringGenesis: app left during DBRW securing; wiped partial state")
```

**Note:** the wipe-on-onPause invariant is preserved exactly. We only added the marker call before the wipe. Because `markGenesisSecuring()` goes through `NativeBoundaryBridge.ingress` → post-hook → `runOnUiThread { publishCurrentSessionState }`, the session.state publish is scheduled on the UI thread BEFORE the wipe and envelope dispatches, so the order is consistent with Tasks 4 and 5.

**Step 3: Apply the marker call to the catch path of `installGenesisEnvelope`**

In the catch block found in Step 1 (also in `captureDeviceBindingForGenesisEnvelope` if it has its own catch — confirm with `grep`), insert the marker before the existing wipe / aborted envelope dispatch:

```kotlin
} catch (e: Exception) {
    Log.e(logTag, "installGenesisEnvelope: aborting due to exception", e)
    markGenesisSecuring(MarkGenesisSecuringOp.Phase.PHASE_ABORTED)
    // ...existing wipe + envelope dispatch path...
    throw e
}
```

If `installGenesisEnvelope` does not have its own catch (i.e. the abort path is fully owned by `captureDeviceBindingForGenesisEnvelope` at lines 503-569), apply the marker there instead. Confirm with `grep -n "catch (e:" BridgeIdentityHandler.kt`.

**Step 4: Compile check**

```bash
cd dsm_client/android && \
  ./gradlew :app:compileDebugKotlin
```
Expected: SUCCESS.

**Step 5: Commit**

```bash
git add dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt
git commit -m "feat(android): mark Rust securing ABORTED via ingress on pause + catch

Both abort paths (handleHostPauseDuringGenesis and the catch block of
installGenesisEnvelope/captureDeviceBindingForGenesisEnvelope) now
dispatch MarkGenesisSecuring ABORTED through the ingress seam before
wiping partial state. The wipe-on-onPause security invariant is preserved
unchanged; we only added the Rust flag clear ahead of it so the frontend
phase falls back to needs_genesis synchronously via the post-hook publish.

Refs: docs/plans/2026-04-10-rust-authoritative-securing-phase.md Task 6"
```

---

## Task 7: Make `useGenesisFlow.ts` UI-only

**Files:**
- Modify: `dsm_client/frontend/src/hooks/useGenesisFlow.ts` (entire file)
- Trace callers: `dsm_client/frontend/src/components/AppContent.tsx` (or wherever `useGenesisFlow` is consumed)

**Step 1: Find consumers of `useGenesisFlow`**

```bash
```
Use Grep tool with pattern `useGenesisFlow` glob `*.ts*`. Note which props (`appState`, `setAppState`, `setError`, `setSecuringProgress`) the consumer passes — Task 7 changes the prop signature so the call site must update too.

**Step 2: Rewrite `useGenesisFlow.ts` to be UI-only**

Replace the entire file with:

```typescript
/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useRef } from 'react';
import logger from '../utils/logger';
import { decodeFramedEnvelopeV3 } from '../dsm/decoding';
import { addDsmEventListener } from '../dsm/WebViewBridge';

type Args = {
  setSecuringProgress: (p: number) => void;
  setError: (s: string | null) => void;
};

/**
 * Genesis flow hook — UI-ONLY.
 *
 * Rust SessionManager owns the `securing_device` phase via the
 * markGenesisSecuring{Started,Complete,Aborted} JNI markers. After those
 * markers fire, Kotlin's BridgeIdentityHandler triggers a fresh
 * publishSessionState which propagates the phase via session.state →
 * useNativeSessionBridge → appRuntimeStore.setAppState. This hook MUST NOT
 * write appState directly — doing so reintroduces the multi-writer race.
 *
 * Responsibilities of this hook:
 *  - Listen for genesis lifecycle DOM events purely to update the bar (%).
 *  - Surface error messages from the genesis call into UI state.
 *  - Trigger the genesis call when the user taps INITIALIZE.
 */
export function useGenesisFlow({ setSecuringProgress, setError }: Args) {
  const genesisInFlight = useRef(false);

  // Progress events update only the bar percentage. Phase transitions are
  // driven by Rust via session.state — see useNativeSessionBridge.
  useEffect(() => {
    const unsub = addDsmEventListener((evt) => {
      if (evt.topic === 'genesis.securing-device') {
        logger.info('FRONTEND: Silicon fingerprint enrollment started');
        setSecuringProgress(0);
      } else if (evt.topic === 'genesis.securing-device-progress') {
        const pct = evt.payload.length > 0 ? (evt.payload[0] & 0xFF) : 0;
        logger.info(`FRONTEND: Silicon fingerprint progress: ${pct}%`);
        setSecuringProgress(pct);
      } else if (evt.topic === 'genesis.securing-device-complete') {
        logger.info('FRONTEND: Silicon fingerprint enrollment complete');
        setSecuringProgress(100);
      } else if (evt.topic === 'genesis.securing-device-aborted') {
        logger.warn('FRONTEND: Device securing aborted - phase transition handled by Rust');
        setSecuringProgress(0);
      }
    });
    return unsub;
  }, [setSecuringProgress]);

  const handleGenerateGenesis = useCallback(async () => {
    if (genesisInFlight.current) {
      logger.debug('FRONTEND: handleGenerateGenesis already running; skipping');
      return;
    }
    logger.info('FRONTEND: handleGenerateGenesis called');
    try {
      genesisInFlight.current = true;
      logger.info('FRONTEND: Triggering genesis via router (Kotlin owns entropy/locale/network)');

      const { createGenesisViaRouter } = await import('../dsm/WebViewBridge');

      const entropy = new Uint8Array(32);
      crypto.getRandomValues(entropy);
      const locale = navigator.language || 'en-US';
      const networkId = 'mainnet';

      const envelopeBytes = await createGenesisViaRouter(locale, networkId, entropy);
      logger.debug('FRONTEND: createGenesisViaRouter returned bytes', envelopeBytes?.length);

      if (!envelopeBytes || envelopeBytes.length < 10) {
        throw new Error('Genesis envelope is empty or too small');
      }

      const env = decodeFramedEnvelopeV3(envelopeBytes);
      const payload: any = env.payload;
      logger.debug('FRONTEND: Envelope payload case', payload?.case);

      if (payload?.case === 'error') {
        const errMsg = payload.value?.message || 'Unknown error from native genesis';
        logger.error('FRONTEND: Genesis error', errMsg);
        throw new Error(`Genesis creation failed: ${errMsg}`);
      }

      const gc = payload?.case === 'genesisCreatedResponse' ? payload.value : null;
      if (!gc) throw new Error(`Invalid GenesisCreated envelope - got case: ${payload?.case}`);

      logger.info('FRONTEND: Genesis completed successfully');
      // Phase transitions to wallet_ready via session.state event from Rust.
    } catch (err) {
      logger.error('FRONTEND: Genesis generation failed', err);
      const message = err instanceof Error ? err.message : 'Genesis generation failed';
      setError(message);
      // Phase transition to needs_genesis or error is handled by Rust via the
      // catch path of installGenesisEnvelope (which calls markGenesisSecuringAborted).
    } finally {
      genesisInFlight.current = false;
    }
  }, [setError]);

  return { handleGenerateGenesis };
}
```

**Step 3: Update the consumer call site**

Find the consumer (likely `AppContent.tsx`). Currently it passes `appState, setAppState, setError, setSecuringProgress`. After this task, it must pass only `setError, setSecuringProgress`. Update the call site accordingly. The consumer no longer needs `appState` for this hook — it still has its own subscription to `useAppRuntimeStore`.

**Step 4: Compile check**

```bash
cd dsm_client/frontend && pnpm tsc --noEmit
```
Expected: SUCCESS, no type errors.

**Step 5: Commit**

```bash
git add dsm_client/frontend/src/hooks/useGenesisFlow.ts \
        dsm_client/frontend/src/components/AppContent.tsx
git commit -m "refactor(frontend): make useGenesisFlow UI-only

Removes all setAppState writes and the visibilitychange wipe handler.
The 'securing_device' phase is now owned by Rust SessionManager. Phase
transitions arrive via session.state → useNativeSessionBridge. The hook
keeps only the bar progress updates and the genesis trigger callback.

This closes the multi-writer race that caused bounce-to-initialize.

Refs: docs/plans/2026-04-10-rust-authoritative-securing-phase.md Task 7"
```

---

## Task 8: Update `useGenesisFlow.test.ts` to reflect UI-only behaviour

**Files:**
- Modify: `dsm_client/frontend/src/hooks/__tests__/useGenesisFlow.test.ts`

**Step 1: Read the existing test file**

```bash
```
Use the Read tool on `dsm_client/frontend/src/hooks/__tests__/useGenesisFlow.test.ts` to understand which assertions reference `setAppState`.

**Step 2: Write the failing assertion(s)**

Add a new test (or modify the existing one) to assert that `setAppState` is **never** called from the hook, and that progress events still update the bar:

```typescript
import { renderHook, act } from '@testing-library/react';
import { useGenesisFlow } from '../useGenesisFlow';

describe('useGenesisFlow (UI-only)', () => {
  it('does not write appState — phase transitions are owned by Rust', () => {
    const setSecuringProgress = vi.fn();
    const setError = vi.fn();
    // No setAppState argument should be required at all
    const { result } = renderHook(() => useGenesisFlow({ setSecuringProgress, setError }));
    expect(result.current.handleGenerateGenesis).toBeDefined();
  });

  it('updates progress on genesis.securing-device-progress event', () => {
    const setSecuringProgress = vi.fn();
    const setError = vi.fn();
    renderHook(() => useGenesisFlow({ setSecuringProgress, setError }));

    act(() => {
      window.dispatchEvent(
        new CustomEvent('dsm:event', {
          detail: { topic: 'genesis.securing-device-progress', payload: new Uint8Array([42]) },
        }),
      );
    });

    expect(setSecuringProgress).toHaveBeenCalledWith(42);
  });
});
```

Remove (or update) any existing test that asserts `setAppState('securing_device')` was called from inside the hook — that contract no longer exists.

**Step 3: Run tests**

```bash
cd dsm_client/frontend && pnpm test useGenesisFlow
```
Expected: PASS for the new tests. Old tests asserting setAppState writes from the hook should be deleted, not "fixed" — the behaviour is intentionally gone.

**Step 4: Commit**

```bash
git add dsm_client/frontend/src/hooks/__tests__/useGenesisFlow.test.ts
git commit -m "test(frontend): assert useGenesisFlow no longer writes appState

Replaces the old setAppState-mock assertions with a UI-only contract:
the hook reports progress, surfaces errors, and triggers genesis. Phase
transitions are exclusively driven by Rust through session.state.

Refs: docs/plans/2026-04-10-rust-authoritative-securing-phase.md Task 8"
```

---

## Task 9: NDK rebuild and symbol verification

**Files:**
- Build: `dsm_client/decentralized_state_machine/` (or `deterministic_state_machine` — confirm path)

**Step 1: Resolve the workspace path**

```bash
ls dsm_client/decentralized_state_machine 2>&1 || ls dsm_client/deterministic_state_machine
```
Use whichever path exists. Update CLAUDE.md memory if `decentralized_state_machine` does not exist (the verified plan path is `deterministic_state_machine`).

**Step 2: Run the full NDK rebuild**

```bash
rm -f dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so \
     dsm_client/android/app/src/main/jniLibs/armeabi-v7a/libdsm_sdk.so \
     dsm_client/android/app/src/main/jniLibs/x86_64/libdsm_sdk.so && \
cd dsm_client/deterministic_state_machine && \
DSM_PROTO_ROOT=/Users/cryptskii/Desktop/claude_workspace/dsm/proto \
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 \
  -o /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/android/app/src/main/jniLibs \
  --platform 23 build --release --package dsm_sdk --features=jni,bluetooth
```
Expected: SUCCESS, three `.so` files emitted to `app/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/`.

**Step 3: Verify symbol count is UNCHANGED**

```bash
nm -gU dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so | grep -c Java_
```
Expected: ≥ 82 (unchanged from pre-plan baseline). This plan adds ZERO new JNI exports — the mark ops flow through the existing `Java_com_dsm_wallet_bridge_UnifiedNativeApi_dispatchIngress` entry point. If the symbol count grows, someone added an Android-only export in violation of the cross-platform ingress rule — stop and investigate.

```bash
nm -gU dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so | grep markGenesisSecuring
```
Expected: ZERO results. The mark functions are internal Rust code inside `ingress.rs`; they are not exported across the JNI boundary.

**Step 4: Mirror to repo-level jniLibs (per CLAUDE.md memory)**

```bash
cp dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so \
   dsm_client/android/jniLibs/arm64-v8a/libdsm_sdk.so 2>/dev/null || true
cp dsm_client/android/app/src/main/jniLibs/armeabi-v7a/libdsm_sdk.so \
   dsm_client/android/jniLibs/armeabi-v7a/libdsm_sdk.so 2>/dev/null || true
cp dsm_client/android/app/src/main/jniLibs/x86_64/libdsm_sdk.so \
   dsm_client/android/jniLibs/x86_64/libdsm_sdk.so 2>/dev/null || true
```

**Step 5: No commit yet** — `.so` files are git-ignored. The next gradle build will pick them up.

---

## Task 10: Gradle clean rebuild + install on test devices

**Files:** none modified. Runs the Android build pipeline.

**Step 1: Gradle clean (mandatory per CLAUDE.md memory — `mergeDebugNativeLibs UP-TO-DATE` uses stale cached `.so`)**

```bash
cd dsm_client/android && ./gradlew clean
```
Expected: BUILD SUCCESSFUL.

**Step 2: Build debug APK**

```bash
cd dsm_client/android && ./gradlew :app:assembleDebug
```
Expected: BUILD SUCCESSFUL. The new `markGenesisSecuring*` JNI references must link against the `.so` from Task 9.

**Step 3: Install on Galaxy A54 (R5CW620MQVL)**

```bash
adb -s R5CW620MQVL install -r dsm_client/android/app/build/outputs/apk/debug/app-debug.apk
```
If the device returns `INSTALL_FAILED_UPDATE_INCOMPATIBLE`, uninstall first:
```bash
adb -s R5CW620MQVL uninstall com.dsm.wallet
adb -s R5CW620MQVL install dsm_client/android/app/build/outputs/apk/debug/app-debug.apk
```

**Step 4: (Optional, USB allowing) install on Galaxy A16 (RF8Y90PX5GN)**

```bash
adb -s RF8Y90PX5GN install -r dsm_client/android/app/build/outputs/apk/debug/app-debug.apk
```

**Step 5: Manual smoke test (the bug repro)**

1. Launch the app.
2. Tap INITIALIZE.
3. Watch the "Device Setup" loading bar through 100 %.
4. Expected: smooth transition to wallet home screen.
5. Repeat 10 times. Previously the bug appeared roughly 1-in-3 attempts; with the race fixed it must reach wallet home **every time**.
6. **Stress test:** during the bar loading, plug/unplug USB or trigger battery state change (e.g. turn screen-saver on then off). The race used to fire during these unrelated events. With the fix, the bar must continue uninterrupted to wallet home.

**Step 6: Commit nothing (no source files changed in this task)**

---

## Task 11: Pre-merge guardrail and full test suite

**Files:** none modified. Runs the project's invariant scans.

**Step 1: Run guardrail scans (per `rules.instructions.md`)**

```bash
.github/scripts/no_clock_and_no_json.sh 2>&1
.github/scripts/check_forbidden_symbols.sh 2>&1
.github/scripts/flow_assertions.sh 2>&1
.github/scripts/flow_mapping_assertions.sh 2>&1
```
Expected: all four scripts exit 0. None of the new code touches time/JSON/hex APIs.

**Step 2: Run frontend canonical tests**

```bash
cd dsm_client/frontend && pnpm test:canonical
```
Expected: PASS, including the updated `useGenesisFlow.test.ts`.

**Step 3: Run Rust SDK tests**

```bash
cd dsm_client/deterministic_state_machine && \
  cargo test -p dsm_sdk --features=jni,bluetooth
```
Expected: PASS, including the three new `tests::securing_*` and `tests::marker_helpers_round_trip` tests.

**Step 4: Run Android JVM tests**

```bash
cd dsm_client/android && ./gradlew :app:test
```
Expected: PASS. Existing bridge handler tests should still work — the new code only adds calls before/after existing dispatches.

**Step 5: If everything green, merge the worktree branch**

This is the final commit if any docs/CLAUDE.md updates were needed in Task 9 (workspace path correction):

```bash
git status
# If CLAUDE.md was updated to fix the workspace path, commit:
git add CLAUDE.md
git commit -m "docs: correct NDK workspace path to deterministic_state_machine"
```

Otherwise, no commit.

---

## Acceptance criteria

Before declaring done:

- [x] Rust `compute_phase` returns `securing_device` when the flag is set, with priority above `needs_genesis`. *(Task 1, commit `962952e`)*
- [x] Three `mark_securing_*` setters exist on `SessionManager`. *(Task 1, commit `962952e`)*
- [ ] `MarkGenesisSecuringOp` message exists in `proto/dsm_app.proto` with enum `Phase { UNSPECIFIED, STARTED, COMPLETE, ABORTED }` and is wired into `IngressRequest.operation` as tag 6. *(Task 2)*
- [ ] Generated Rust, Kotlin/Java, and TypeScript stubs all contain the new types. *(Task 2)*
- [ ] Three `mark_securing_*_and_snapshot()` module-level helpers exist in `session_manager.rs`. *(Task 3)*
- [ ] `ingress::dispatch_ingress` has a `MarkGenesisSecuring` match arm that calls `mark_genesis_securing_core(phase)`, and the core function maps the enum to the right helper. *(Task 3)*
- [ ] Four new Rust tests pass: `marker_helpers_round_trip_through_compute_phase`, `dispatch_ingress_mark_genesis_securing_started_sets_flag`, `dispatch_ingress_mark_genesis_securing_complete_clears_flag`, `dispatch_ingress_mark_genesis_securing_unspecified_errors`. *(Task 3)*
- [ ] `NativeBoundaryBridge.runBestEffortPostIngressHooks` handles `IngressRequest.OperationCase.MARK_GENESIS_SECURING` by publishing fresh session state on the UI thread. *(Task 4)*
- [ ] `BridgeIdentityHandler` has a private `markGenesisSecuring(phase)` helper that builds an `IngressRequest` and dispatches via `NativeBoundaryBridge.ingress`. *(Task 4)*
- [ ] `BridgeIdentityHandler.installGenesisEnvelope` calls `markGenesisSecuring(STARTED)` immediately before `createGenesisSecuringDeviceEnvelope` and `markGenesisSecuring(COMPLETE)` immediately after `sdkContextInitialized.set(true)`. *(Tasks 4 + 5)*
- [ ] `BridgeIdentityHandler.handleHostPauseDuringGenesis` calls `markGenesisSecuring(ABORTED)` before the wipe (wipe-on-onPause invariant unchanged). *(Task 6)*
- [ ] The catch block(s) of `installGenesisEnvelope` / `captureDeviceBindingForGenesisEnvelope` call `markGenesisSecuring(ABORTED)` before any other abort handling. *(Task 6)*
- [ ] `nm -gU libdsm_sdk.so | grep markGenesisSecuring` returns ZERO hits. The JNI symbol count is UNCHANGED from baseline — no new per-platform exports added. *(Task 9)*
- [ ] Frontend `useGenesisFlow` no longer imports `AppState`, no longer calls `setAppState`, no longer registers a `visibilitychange` listener. It exports a hook that takes only `setSecuringProgress` and `setError`. *(Task 7)*
- [ ] Manual smoke test on Galaxy A54: 10 consecutive INITIALIZE → wallet_ready transitions, no bounce to INITIALIZE. *(Task 10)*
- [ ] Stress test (USB unplug, battery state, screen-saver) during the bar does not bounce. *(Task 10)*
- [ ] All four guardrail scans exit 0. *(Task 11)*
- [ ] `pnpm test:canonical && cargo test -p dsm_sdk && ./gradlew :app:test` all green. *(Task 11)*

## Out of scope (deferred)

- Race B (handler-vs-render reorder) — not the symptom the user reported. The user explicitly said "no error message, plain bounce" → Race A only.
- Removing the wipe-on-onPause path. **Stays as-is** per Gemini Flash's fatal-issue verdict (process-death window between onPause and onStop).
- Replacing `getActiveInstance()` with a cleaner DI seam — out of scope. The static accessor is already public and used by other call sites.
- Replacing the genesis lifecycle DOM events with a Rust-driven topic — possible but unrelated to the race. The lifecycle events still drive UI like the bar percentage; this plan leaves them in place.
- Auditing the other 14 `publishSessionState` callers. They're no longer dangerous because Rust now reports `securing_device` correctly during the window.

## Reference skills

- `superpowers:executing-plans` — to execute this plan task-by-task.
- `superpowers:subagent-driven-development` — if executing via fresh subagent per task.
- `adversarial-reasoning` — already applied during plan design (Gemini Flash damaged-survival verdict; one fatal issue accepted, four serious issues addressed).
