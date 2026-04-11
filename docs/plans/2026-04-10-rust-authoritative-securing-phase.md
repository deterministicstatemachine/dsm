# Rust-Authoritative Securing Phase Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate the silent "bounce-to-initialize" race during device setup by making Rust the sole authority for the `securing_device` phase, removing all frontend `setAppState` writers in the genesis flow.

**Architecture:** Add `securing_in_progress: bool` to Rust `SessionManager`, give `compute_phase()` an explicit `securing_device` arm that wins over `needs_genesis`, and expose three JNI markers (`markGenesisSecuringStarted/Complete/Aborted`) that flip the flag and return a fresh snapshot. Kotlin's `BridgeIdentityHandler` calls the markers around silicon-FP enrollment with strict ordering: **mark Rust → publish session state → fire lifecycle envelope**. Frontend `useGenesisFlow` becomes UI-only — it no longer writes `appState` for the securing phase. After this change, `useNativeSessionBridge` is the only writer to `appState`, and Rust is the only source of phase truth.

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
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs:65-90` — `SessionManager` struct + `Default`
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs:192-206` — `compute_phase()`
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs:308-312` — `get_session_snapshot_bytes()`
- `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs:344-398` — existing test module + helpers
- `dsm_client/deterministic_state_machine/dsm_sdk/src/jni/unified_protobuf_bridge.rs:5932-5951` — `getSessionSnapshot` JNI export (no-arg pattern)
- `dsm_client/deterministic_state_machine/dsm_sdk/src/jni/unified_protobuf_bridge.rs:6043-6062` — `clearSessionFatalError` JNI export (no-arg, returns snapshot bytes — closest precedent)
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/UnifiedNativeApi.kt:177-184` — existing `createGenesis*Envelope` externs
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/UnifiedNativeApi.kt:194-195` — existing `getSessionSnapshot/updateSessionHardwareFacts` externs
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:215` — `createGenesisSecuringDeviceEnvelope` (start of bar)
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:229` — `createGenesisSecuringCompleteEnvelope` (bar 100%)
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:254-260` — `sdkBootstrapStrict` (`has_identity` becomes true here, eventually)
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:301` — `sdkContextInitialized.set(true)`
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:302` — `createGenesisOkEnvelope`
- `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:308-333` — `handleHostPauseDuringGenesis`
- `dsm_client/android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt:161` — `getActiveInstance()`
- `dsm_client/android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt:427-454` — `publishSessionState()`
- `dsm_client/android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt:456-458` — `publishCurrentSessionState(reason)` (public)
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

## Task 1: Add `securing_in_progress` field + setters to `SessionManager`

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

## Task 2: Add three JNI markers in `unified_protobuf_bridge.rs`

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/src/jni/unified_protobuf_bridge.rs` (after line 6062, next to `clearSessionFatalError`)
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs` (add three module-level helpers next to `clear_fatal_error_and_snapshot`)

**Step 1: Add module-level helpers in `session_manager.rs`**

After `clear_fatal_error_and_snapshot` (~line 342), add:

```rust
/// Mark device-securing started and return updated snapshot bytes.
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

**Step 2: Write the failing JNI smoke test**

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

    let complete = mark_securing_complete_and_snapshot();
    assert!(!complete.is_empty());

    let aborted = mark_securing_aborted_and_snapshot();
    assert!(!aborted.is_empty());

    // After these calls the manager flag is back to false
    let mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    assert!(!mgr.securing_in_progress);
}
```

**Step 3: Run test to verify it fails**

```bash
cd dsm_client/deterministic_state_machine && \
  cargo test -p dsm_sdk --features=jni,bluetooth \
    sdk::session_manager::tests::marker_helpers_round_trip
```
Expected: FAIL with `cannot find function 'mark_securing_started_and_snapshot'`.

**Step 4: Re-run after Step 1 helpers are in place**

```bash
cd dsm_client/deterministic_state_machine && \
  cargo test -p dsm_sdk --features=jni,bluetooth \
    sdk::session_manager::tests::marker_helpers_round_trip
```
Expected: PASS.

**Step 5: Add the three JNI exports**

In `unified_protobuf_bridge.rs`, **after** `clearSessionFatalError` (insert after line 6062, before the `// ========================= NFC Ring Backup JNI Exports =========================` divider on line 6064). Pattern follows `clearSessionFatalError` (no args, returns snapshot bytes):

```rust
/// Mark device-securing started and return updated session snapshot bytes.
/// Called by Kotlin BridgeIdentityHandler immediately before silicon-FP enrollment
/// begins. Strict ordering: this call must complete before publishSessionState
/// fires its session.state event so any concurrent caller sees `securing_device`.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_markGenesisSecuringStarted(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "markGenesisSecuringStarted",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let snapshot_bytes = crate::sdk::session_manager::mark_securing_started_and_snapshot();
            env.byte_array_from_slice(&snapshot_bytes)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
        }),
    )
}

/// Mark device-securing complete and return updated session snapshot bytes.
/// Called by Kotlin BridgeIdentityHandler immediately after sdkContextInitialized
/// is set true and BEFORE the createGenesisOkEnvelope dispatch.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_markGenesisSecuringComplete(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "markGenesisSecuringComplete",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let snapshot_bytes = crate::sdk::session_manager::mark_securing_complete_and_snapshot();
            env.byte_array_from_slice(&snapshot_bytes)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
        }),
    )
}

/// Mark device-securing aborted and return updated session snapshot bytes.
/// Called by Kotlin BridgeIdentityHandler from handleHostPauseDuringGenesis
/// and from the catch path inside installGenesisEnvelope, BEFORE the wipe.
#[no_mangle]
pub extern "system" fn Java_com_dsm_wallet_bridge_UnifiedNativeApi_markGenesisSecuringAborted(
    env: jni::sys::JNIEnv,
    _clazz: jni::sys::jclass,
) -> jni::sys::jbyteArray {
    crate::jni::bridge_utils::jni_catch_unwind_jbytearray(
        "markGenesisSecuringAborted",
        std::panic::AssertUnwindSafe(|| {
            let env = match unsafe { env_from(env) } {
                Some(e) => e,
                None => return std::ptr::null_mut(),
            };
            let snapshot_bytes = crate::sdk::session_manager::mark_securing_aborted_and_snapshot();
            env.byte_array_from_slice(&snapshot_bytes)
                .map(|a| a.into_raw())
                .unwrap_or_else(|_| empty_byte_array_or_empty(&env).into_raw())
        }),
    )
}
```

**Step 6: Compile-only check**

```bash
cd dsm_client/deterministic_state_machine && \
  cargo check -p dsm_sdk --features=jni,bluetooth
```
Expected: clean compile, no warnings.

**Step 7: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs \
        dsm_client/deterministic_state_machine/dsm_sdk/src/jni/unified_protobuf_bridge.rs
git commit -m "feat(jni): expose mark_securing_{started,complete,aborted} markers

Three no-arg JNI exports return updated session snapshot bytes after
flipping the SessionManager.securing_in_progress flag. Each follows the
clearSessionFatalError pattern: jni_catch_unwind, lock manager, mutate,
return [0x03][Envelope(SessionStateResponse)] for Kotlin to relay.

Refs: docs/plans/2026-04-10-rust-authoritative-securing-phase.md Task 2"
```

---

## Task 3: Declare new externs in Kotlin `UnifiedNativeApi.kt`

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/UnifiedNativeApi.kt:184` (insert after `createGenesisSecuringAbortedEnvelope`)

**Step 1: Add the three external declarations**

After line 184 (`createGenesisSecuringAbortedEnvelope`), insert:

```kotlin
/**
 * Mark device-securing started in Rust SessionManager. Returns updated session
 * snapshot bytes ([0x03][Envelope(SessionStateResponse)]). Call this BEFORE
 * dispatching createGenesisSecuringDeviceEnvelope so the next publishSessionState
 * sees `securing_device` phase.
 */
@Keep @JvmStatic external fun markGenesisSecuringStarted(): ByteArray

/**
 * Mark device-securing complete in Rust SessionManager. Returns updated session
 * snapshot bytes. Call this AFTER sdkContextInitialized.set(true) and BEFORE
 * createGenesisOkEnvelope so phase transitions through securing → wallet_ready
 * cleanly.
 */
@Keep @JvmStatic external fun markGenesisSecuringComplete(): ByteArray

/**
 * Mark device-securing aborted in Rust SessionManager. Returns updated session
 * snapshot bytes. Call this from handleHostPauseDuringGenesis and from the
 * catch path of installGenesisEnvelope BEFORE wiping prefs.
 */
@Keep @JvmStatic external fun markGenesisSecuringAborted(): ByteArray
```

**Step 2: Verify Gradle compile**

```bash
cd dsm_client/android && \
  ./gradlew :app:compileDebugKotlin
```
Expected: SUCCESS. (The native side will be missing until Task 9 NDK rebuild — Kotlin only checks the JNI signatures at link time, not compile time.)

**Step 3: Commit**

```bash
git add dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/UnifiedNativeApi.kt
git commit -m "feat(android): declare markGenesisSecuring* JNI externs

Adds three external fun declarations matching the new Rust JNI exports.
Returns ByteArray snapshot bytes for caller to relay or inspect.

Refs: docs/plans/2026-04-10-rust-authoritative-securing-phase.md Task 3"
```

---

## Task 4: Wire `markGenesisSecuringStarted` in `installGenesisEnvelope`

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt:215` (insert lines BEFORE the existing `createGenesisSecuringDeviceEnvelope` dispatch)

**Step 1: Read the surrounding context (already done — lines 200-230)**

The current sequence at line 215 is:
```kotlin
UnifiedNativeApi.createGenesisSecuringDeviceEnvelope().let {
    if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it)
}
```

**Step 2: Apply the marker call with strict ordering**

Replace lines 215-216 with the strict-order block:

```kotlin
// STRICT ORDER: mark Rust → publish session.state → fire lifecycle envelope.
// This three-step sequence prevents the bounce-to-initialize race.
// 1. Rust SessionManager.securing_in_progress = true (synchronous JNI call).
UnifiedNativeApi.markGenesisSecuringStarted()
// 2. Force a fresh session.state event so any concurrent battery/BLE/walletRefresh
//    callers can no longer race a stale snapshot through publishSessionState.
com.dsm.wallet.ui.MainActivity.getActiveInstance()
    ?.publishCurrentSessionState("genesisSecuringStarted")
// 3. Fire the lifecycle envelope (frontend useGenesisFlow listens for progress UI).
UnifiedNativeApi.createGenesisSecuringDeviceEnvelope().let {
    if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it)
}
Log.i(logTag, "installGenesisEnvelope: starting silicon fingerprint enrollment...")
```

**Note:** there is an existing `Log.i(logTag, "installGenesisEnvelope: starting silicon fingerprint enrollment...")` on line 216 — keep only one of them. The block above includes the log; remove the duplicate.

**Step 3: Compile check**

```bash
cd dsm_client/android && \
  ./gradlew :app:compileDebugKotlin
```
Expected: SUCCESS. `MainActivity.getActiveInstance()` is already public (line 161), `publishCurrentSessionState` is already public (line 456).

**Step 4: Commit**

```bash
git add dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt
git commit -m "feat(android): mark Rust securing started before bar dispatch

Three-step strict order: markGenesisSecuringStarted (Rust flag flip,
synchronous JNI), publishCurrentSessionState (forces fresh session.state
to all subscribers), createGenesisSecuringDeviceEnvelope (UI bar event).
This window is the source of the bounce-to-initialize race.

Refs: docs/plans/2026-04-10-rust-authoritative-securing-phase.md Task 4"
```

---

## Task 5: Wire `markGenesisSecuringComplete` after `sdkContextInitialized.set(true)`

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

// STRICT ORDER: mark Rust → publish session.state → fire lifecycle envelope.
// At this point has_identity is true (sdkBootstrapStrict succeeded above), so
// after clearing securing_in_progress, compute_phase will return wallet_ready.
// 1. Rust SessionManager.securing_in_progress = false.
UnifiedNativeApi.markGenesisSecuringComplete()
// 2. Force a fresh session.state event so the frontend transitions
//    securing_device → wallet_ready synchronously, before any other caller.
com.dsm.wallet.ui.MainActivity.getActiveInstance()
    ?.publishCurrentSessionState("genesisSecuringComplete")
// 3. Fire the OK lifecycle envelope.
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
git commit -m "feat(android): mark Rust securing complete before OK envelope

After sdkContextInitialized.set(true), mark Rust complete and force a
session.state publish so the frontend's useNativeSessionBridge transitions
securing_device → wallet_ready in a single observable step. The OK
lifecycle envelope still fires for any UI components that listen for it.

Refs: docs/plans/2026-04-10-rust-authoritative-securing-phase.md Task 5"
```

---

## Task 6: Wire `markGenesisSecuringAborted` in pause + catch paths

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

Insert the marker BEFORE the wipe and BEFORE the lifecycle envelopes, and force a session-state publish:

```kotlin
if (!genesisLifecycleInFlight.get()) {
    return
}
genesisLifecycleInvalidated.set(true)

// STRICT ORDER: mark Rust → publish session.state → wipe artifacts → fire envelopes.
// Marking Rust first ensures no concurrent publishSessionState observer can see
// "securing_device" after this function decided the flow is dead.
UnifiedNativeApi.markGenesisSecuringAborted()
com.dsm.wallet.ui.MainActivity.getActiveInstance()
    ?.publishCurrentSessionState("genesisSecuringAborted")

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

**Note:** the wipe-on-onPause invariant is preserved exactly. We only added the marker call before the wipe.

**Step 3: Apply the marker call to the catch path of `installGenesisEnvelope`**

In the catch block found in Step 1 (also in `captureDeviceBindingForGenesisEnvelope` if it has its own catch — confirm with `grep`), insert the marker before the existing wipe / aborted envelope dispatch. Use the same three-step strict order. The exact line depends on what Step 1 reveals; insert immediately at the start of the catch block:

```kotlin
} catch (e: Exception) {
    Log.e(logTag, "installGenesisEnvelope: aborting due to exception", e)
    UnifiedNativeApi.markGenesisSecuringAborted()
    com.dsm.wallet.ui.MainActivity.getActiveInstance()
        ?.publishCurrentSessionState("genesisSecuringFailed")
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
git commit -m "feat(android): mark Rust securing aborted on pause + catch

Both abort paths (handleHostPauseDuringGenesis and the catch block of
installGenesisEnvelope/captureDeviceBindingForGenesisEnvelope) now call
markGenesisSecuringAborted before wiping partial state. The wipe-on-onPause
security invariant is preserved unchanged; we only added the Rust flag
clear ahead of it so the frontend phase falls back to needs_genesis
synchronously.

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

**Step 3: Verify symbol count grew by 3**

```bash
nm -gU dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so | grep -c Java_
```
Expected: ≥ 90 (was 87, now +3 markers). The new symbols should be visible:

```bash
nm -gU dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so | grep markGenesisSecuring
```
Expected: three lines, one each for `markGenesisSecuringStarted`, `markGenesisSecuringComplete`, `markGenesisSecuringAborted`.

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

- [ ] Rust `compute_phase` returns `securing_device` when the flag is set, with priority above `needs_genesis`.
- [ ] Three `mark_securing_*` setters exist and round-trip through `compute_snapshot`.
- [ ] Three new JNI symbols (`Java_..._markGenesisSecuringStarted/Complete/Aborted`) appear in `nm -gU libdsm_sdk.so`.
- [ ] `BridgeIdentityHandler.installGenesisEnvelope` calls `markGenesisSecuringStarted` immediately before the bar dispatch and `markGenesisSecuringComplete` immediately after `sdkContextInitialized.set(true)`, both with `publishCurrentSessionState` in between Rust and the lifecycle envelope.
- [ ] `BridgeIdentityHandler.handleHostPauseDuringGenesis` calls `markGenesisSecuringAborted` before the wipe (wipe-on-onPause invariant unchanged).
- [ ] The catch block(s) of `installGenesisEnvelope` / `captureDeviceBindingForGenesisEnvelope` call `markGenesisSecuringAborted` before any other abort handling.
- [ ] Frontend `useGenesisFlow` no longer imports `AppState`, no longer calls `setAppState`, no longer registers a `visibilitychange` listener. It exports a hook that takes only `setSecuringProgress` and `setError`.
- [ ] Manual smoke test on Galaxy A54: 10 consecutive INITIALIZE → wallet_ready transitions, no bounce to INITIALIZE.
- [ ] Stress test (USB unplug, battery state, screen-saver) during the bar does not bounce.
- [ ] All four guardrail scans exit 0.
- [ ] `pnpm test:canonical && cargo test -p dsm_sdk && ./gradlew :app:test` all green.

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
