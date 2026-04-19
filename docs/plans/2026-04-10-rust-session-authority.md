# Rust Session Authority — Kill Kotlin Logic Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make Rust the sole authority for session state events. Remove all business logic, protobuf inspection, and state caching from Kotlin. Fix the genesis race condition as a side effect.

**Architecture:** Rust pushes session state events proactively via the existing SDK event queue (`push_sdk_event()` + `drain_events()`). Kotlin becomes a pure byte pipe — it forwards hardware facts to Rust, relays bytes between WebView and JNI, and executes OS-level commands (BLE, camera, biometrics) only when Rust tells it to. The frontend already drains events every 250ms via `NativeBoundaryBridge.ts`.

**Tech Stack:** Rust (dsm_sdk), Kotlin (Android bridge), Protobuf (dsm_app.proto), TypeScript (frontend event bridge)

---

## Phase 1: Rust Pushes Session State Events (Additive — No Removals)

Goal: When session-affecting state mutates in Rust, automatically push a `SessionStateUpdated` event. Kotlin's old push path stays active (dual-push, harmless since snapshots are idempotent). This alone fixes the genesis race condition.

### Task 1.1: Add `push_session_state_event()` helper

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs`

**Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `session_manager.rs`:

```rust
#[test]
fn push_session_state_on_sdk_ready() {
    let _g = setup_test_env();
    // Drain any pre-existing events
    crate::event::drain_events(256);

    AppState::set_has_identity(true);
    set_sdk_ready(true);

    let batch = crate::event::drain_events(64);
    let session_events: Vec<_> = batch
        .events
        .iter()
        .filter(|e| e.kind == 1) // SDK_EVENT_KIND_SESSION_STATE
        .collect();
    assert!(
        !session_events.is_empty(),
        "expected at least one SessionState event after set_sdk_ready(true)"
    );
}
```

**Step 2: Run test to verify it fails**

Run: `cd dsm_client/deterministic_state_machine && cargo test -p dsm_sdk push_session_state_on_sdk_ready -- --nocapture`
Expected: FAIL — no session state event is pushed yet.

**Step 3: Write minimal implementation**

Add a public function in `session_manager.rs` (after `get_session_snapshot_bytes()`):

```rust
/// Push a `SessionStateUpdated` event onto the SDK event queue.
/// Called automatically when session-affecting state mutates.
/// Event kind = 1 (SDK_EVENT_KIND_SESSION_STATE).
pub fn push_session_state_event() {
    let snapshot_bytes = get_session_snapshot_bytes();
    crate::event::push_sdk_event(1, snapshot_bytes);
    log::debug!("session_manager: pushed SessionState event to SDK event queue");
}
```

Then hook it into `set_sdk_ready()`:

```rust
pub fn set_sdk_ready(ready: bool) {
    SDK_READY.store(ready, Ordering::SeqCst);
    log::info!("session_manager::set_sdk_ready: SDK_READY={}", ready);
    push_session_state_event();
}
```

**Step 4: Run test to verify it passes**

Run: `cd dsm_client/deterministic_state_machine && cargo test -p dsm_sdk push_session_state_on_sdk_ready -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs
git commit -m "feat: push SessionState event on SDK_READY change"
```

---

### Task 1.2: Hook `set_has_identity()` to push session state

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/app_state.rs`

**Step 1: Write the failing test**

Add to `session_manager.rs` tests:

```rust
#[test]
fn push_session_state_on_identity_set() {
    let _g = setup_test_env();
    set_sdk_ready(true);
    crate::event::drain_events(256); // drain the sdk_ready event

    AppState::set_has_identity(true);

    let batch = crate::event::drain_events(64);
    let session_events: Vec<_> = batch
        .events
        .iter()
        .filter(|e| e.kind == 1)
        .collect();
    assert!(
        !session_events.is_empty(),
        "expected SessionState event after set_has_identity(true)"
    );
}
```

**Step 2: Run test to verify it fails**

Run: `cd dsm_client/deterministic_state_machine && cargo test -p dsm_sdk push_session_state_on_identity_set -- --nocapture`
Expected: FAIL

**Step 3: Implement**

In `app_state.rs`, `set_has_identity()` (line 207):

```rust
pub fn set_has_identity(value: bool) {
    HAS_IDENTITY.store(value, Ordering::SeqCst);
    Self::save_storage();
    crate::sdk::session_manager::push_session_state_event();
}
```

**Step 4: Run test to verify it passes**

Run: `cd dsm_client/deterministic_state_machine && cargo test -p dsm_sdk push_session_state_on_identity_set -- --nocapture`
Expected: PASS

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/app_state.rs dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs
git commit -m "feat: push SessionState event on HAS_IDENTITY change"
```

---

### Task 1.3: Hook lock state and fatal error changes to push

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs`

**Step 1: Write failing tests**

```rust
#[test]
fn push_session_state_on_lock() {
    let _g = setup_test_env();
    set_sdk_ready(true);
    AppState::set_has_identity(true);
    crate::event::drain_events(256);

    {
        let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
        mgr.lock_enabled = true;
        mgr.lock_now();
    }
    push_session_state_event();

    let batch = crate::event::drain_events(64);
    let session_events: Vec<_> = batch.events.iter().filter(|e| e.kind == 1).collect();
    assert!(!session_events.is_empty());
}

#[test]
fn push_session_state_on_fatal_error() {
    let _g = setup_test_env();
    crate::event::drain_events(256);

    set_fatal_error_and_snapshot("test error");

    let batch = crate::event::drain_events(64);
    let session_events: Vec<_> = batch.events.iter().filter(|e| e.kind == 1).collect();
    assert!(!session_events.is_empty());
}
```

**Step 2: Run tests to verify they fail**

Run: `cd dsm_client/deterministic_state_machine && cargo test -p dsm_sdk push_session_state_on_lock push_session_state_on_fatal_error -- --nocapture`

**Step 3: Implement**

Modify `set_fatal_error_and_snapshot()` and `clear_fatal_error_and_snapshot()` to also push events:

```rust
pub fn set_fatal_error_and_snapshot(message: &str) -> Vec<u8> {
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.sync_lock_config_from_app_state();
    mgr.fatal_error = Some(message.to_string());
    log::error!("session_manager::set_fatal_error: {message}");
    let snapshot = mgr.compute_snapshot();
    let bytes = envelope_wrap_snapshot(snapshot.clone());
    // Push event so frontend is notified without polling
    drop(mgr); // release lock before pushing
    crate::event::push_sdk_event(1, envelope_wrap_snapshot(snapshot));
    bytes
}
```

Same pattern for `clear_fatal_error_and_snapshot()`.

For `update_hardware_and_snapshot()` — also push after computing:

```rust
pub fn update_hardware_and_snapshot(facts_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let facts = generated::SessionHardwareFactsProto::decode(facts_bytes)
        .map_err(|e| format!("decode SessionHardwareFactsProto failed: {e}"))?;
    let mut mgr = SESSION_MANAGER.lock().unwrap_or_else(|p| p.into_inner());
    mgr.sync_lock_config_from_app_state();
    mgr.apply_hardware_facts(&facts);
    let snapshot = mgr.compute_snapshot();
    let bytes = envelope_wrap_snapshot(snapshot.clone());
    drop(mgr);
    crate::event::push_sdk_event(1, envelope_wrap_snapshot(snapshot));
    Ok(bytes)
}
```

**Step 4: Run tests**

Run: `cd dsm_client/deterministic_state_machine && cargo test -p dsm_sdk -- --nocapture`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/session_manager.rs
git commit -m "feat: push SessionState events on lock, fatal error, and hardware fact changes"
```

---

### Task 1.4: Verify event drain path end-to-end

**Files:**
- Read: `dsm_client/frontend/src/dsm/NativeBoundaryBridge.ts` (lines 233-264 — `drainSdkEventsOnce()`)
- Read: `dsm_client/frontend/src/dsm/EventBridge.ts` (session.state handling)

**Step 1: Trace the drain path**

Verify that `NativeBoundaryBridge.ts` maps `SDK_EVENT_KIND_SESSION_STATE = 1` to topic `'session.state'` and emits it to `bridgeEvents`. The frontend event bridge should already handle this — confirm no code changes needed.

**Step 2: Check event drain interval**

Current: `EVENT_DRAIN_INTERVAL_MS = 250` (250ms). This means after Rust pushes the event, the frontend will pick it up within 250ms. Acceptable for now. Phase 3 adds instant notification.

**Step 3: Run full test suite**

Run: `cd dsm_client/deterministic_state_machine && cargo test -p dsm_sdk -- --nocapture`
Expected: ALL PASS, no regressions.

**Step 4: Commit (if any frontend adjustments needed)**

---

## Phase 2: Remove Kotlin's Session State Push Path

Goal: Kotlin stops pushing session state to WebView. Rust's event queue is the sole delivery path. Kotlin still forwards hardware facts to Rust (that's transport, not logic).

### Task 2.1: Remove `publishSessionState()` and all call sites from MainActivity

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt`

**Step 1: Identify all call sites** (22 confirmed via grep)

Lines: 130, 378, 511, 514, 776, 783, 935, 948, 961, 1031, 1074, 1181, 1323, 1348, 1370, 1379, 1393, 1503, 1548

**Step 2: Replace session-state-push calls with hardware-facts-only calls**

For calls that need to update hardware facts (battery, BLE, QR, foreground/background), keep the `Unified.updateSessionHardwareFacts(facts)` call but discard the return value. Do NOT dispatch to WebView. Rust's hook from Task 1.3 handles the push.

For calls that don't update hardware facts (bridgeReady, initComplete, envConfig errors), these need a different mechanism — Rust should push the appropriate event kind directly. Convert:
- `"bridgeReady"` → Rust pushes `SDK_EVENT_KIND_BRIDGE_READY = 15`
- `"fatalError"` / `"fatalCleared"` → Already handled by `set_fatal_error_and_snapshot()` push from Task 1.3
- `"envConfigMaterializeFailed"` / `"envUnreadable"` / `"envEmpty"` / `"envMissing"` → Rust pushes `SDK_EVENT_KIND_ENV_CONFIG_ERROR = 7`
- `"initComplete"` → Rust pushes `SDK_EVENT_KIND_SESSION_STATE` (already happens via `set_sdk_ready`)

**Step 3: Remove the function definitions**

Delete `publishSessionState()` (lines 427-453) and `publishCurrentSessionState()` (lines 456-458).

**Step 4: Build and verify**

Run: `cd dsm_client/android && ./gradlew assembleDebug`
Expected: Compiles cleanly. No references to removed functions.

**Step 5: Commit**

```bash
git add dsm_client/android/
git commit -m "refactor: remove publishSessionState from Kotlin — Rust pushes via event queue"
```

---

### Task 2.2: Remove session state push from bridge handlers

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/NativeBoundaryBridge.kt`
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeRouterHandler.kt`
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/NativeHostBridge.kt`

**Step 1: Remove from NativeBoundaryBridge.kt**

Line 39: Remove `MainActivity.getActiveInstance()?.publishCurrentSessionState(method)` for session.lock/unlock. Rust's session_routes handler already pushes via the lock state hook.

**Step 2: Remove from BridgeRouterHandler.kt**

Lines 36-38: Remove the `session.lock`/`session.unlock` special case that calls `publishCurrentSessionState`. The entire `when(name)` block for these two methods can be removed — just let them fall through to the default Rust JNI call.

**Step 3: Remove from NativeHostBridge.kt**

Lines 114, 121, 132, 141, 153, 163: Remove all `publishCurrentSessionState("host_control.*")` calls. Rust pushes hardware status changes via the event queue when it receives updated hardware facts.

**Step 4: Build and verify**

Run: `cd dsm_client/android && ./gradlew assembleDebug`

**Step 5: Commit**

```bash
git add dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/
git commit -m "refactor: remove session state push from all Kotlin bridge handlers"
```

---

### Task 2.3: Remove `dispatchDsmEventOnUi("session.state", ...)` direct push

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt`

**Step 1: Remove direct event dispatch for session.state**

Line 453: This is inside `publishSessionState()` which was already removed in Task 2.1. Verify no other direct `dispatchDsmEventOnUi("session.state", ...)` calls remain.

**Step 2: Convert remaining `dispatchDsmEventOnUi` calls to Rust events**

For non-session events that Kotlin currently dispatches directly:
- `"dsm-identity-ready"` (lines 1179, 1469) → Rust pushes `SDK_EVENT_KIND_IDENTITY_READY = 6` after identity is set
- `"dsm-bridge-ready"` (line 1342) → Rust pushes `SDK_EVENT_KIND_BRIDGE_READY = 15` after bootstrap
- `"dsm-env-config-error"` (lines 1322, 1368, 1377, 1391) → Rust pushes `SDK_EVENT_KIND_ENV_CONFIG_ERROR = 7`
- `"dsm.deterministicSafety"` (line 748) → Rust pushes `SDK_EVENT_KIND_DETERMINISTIC_SAFETY = 11`

For each, add the appropriate `push_sdk_event()` call in the Rust handler that produces the result. Then remove the Kotlin dispatch.

**Step 3: Build and verify**

Run: `cd dsm_client/android && ./gradlew assembleDebug`

**Step 4: Commit**

```bash
git add dsm_client/android/ dsm_client/deterministic_state_machine/
git commit -m "refactor: all events pushed by Rust — remove Kotlin dispatchDsmEventOnUi for protocol events"
```

---

## Phase 3: Instant Event Notification (Eliminate 250ms Polling Latency)

Goal: When Rust pushes any event, immediately notify the frontend to drain instead of waiting up to 250ms.

### Task 3.1: Add JNI callback to notify Kotlin of pending events

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/src/event.rs`
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/src/jni/jni_common.rs`

**Step 1: Add notification function in `jni_common.rs`**

```rust
/// Notify Kotlin that SDK events are available for drain.
/// Called from event.rs::push_event_bytes() on Android targets.
#[cfg(target_os = "android")]
pub fn notify_events_available() {
    with_env(|env| {
        let class = match find_class_with_app_loader(env, "com/dsm/wallet/bridge/SinglePathWebViewBridge") {
            Ok(c) => c,
            Err(e) => {
                log::warn!("notify_events_available: class lookup failed: {e}");
                return;
            }
        };
        if let Err(e) = env.call_static_method(class, "onSdkEventsAvailable", "()V", &[]) {
            log::warn!("notify_events_available: call failed: {e}");
        }
    });
}

#[cfg(not(target_os = "android"))]
pub fn notify_events_available() {
    // No-op on non-Android (tests, desktop)
}
```

**Step 2: Hook into `push_event_bytes()`**

In `event.rs`, after the broadcast send:

```rust
pub fn push_event_bytes(bytes: Vec<u8>) {
    {
        let mut queue = EVENT_QUEUE.lock().expect("event queue poisoned");
        if queue.len() >= EVENT_QUEUE_CAPACITY {
            let _ = queue.pop_front();
        }
        queue.push_back(bytes.clone());
    }
    let _ = EVENT_BROADCAST.send(bytes);
    crate::jni::jni_common::notify_events_available();
}
```

**Step 3: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/src/event.rs dsm_client/deterministic_state_machine/dsm_sdk/src/jni/jni_common.rs
git commit -m "feat: JNI callback to notify Kotlin when SDK events are available"
```

---

### Task 3.2: Kotlin relays notification to WebView

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/SinglePathWebViewBridge.kt`

**Step 1: Add static callback**

```kotlin
companion object {
    @JvmStatic
    fun onSdkEventsAvailable() {
        // Signal frontend to drain immediately
        val instance = activeInstance?.get() ?: return
        instance.activity.runOnUiThread {
            instance.postSignalToWebView("dsm-events-available")
        }
    }
}
```

Where `postSignalToWebView` sends a zero-payload binary message on the MessagePort.

**Step 2: Build and verify**

Run: `cd dsm_client/android && ./gradlew assembleDebug`

**Step 3: Commit**

```bash
git add dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/SinglePathWebViewBridge.kt
git commit -m "feat: Kotlin relays SDK event notification to WebView"
```

---

### Task 3.3: Frontend drains immediately on notification

**Files:**
- Modify: `dsm_client/frontend/src/dsm/NativeBoundaryBridge.ts`

**Step 1: Add listener for immediate drain signal**

```typescript
window.addEventListener('dsm-events-available', () => {
  void drainSdkEventsOnce();
});
```

**Step 2: Increase polling interval as fallback**

Change `EVENT_DRAIN_INTERVAL_MS` from 250 to 2000 (2s fallback). Primary delivery is now signal-driven.

**Step 3: Commit**

```bash
git add dsm_client/frontend/src/dsm/NativeBoundaryBridge.ts
git commit -m "feat: frontend drains SDK events immediately on JNI signal"
```

---

## Phase 4: Move Genesis Orchestration to Rust

Goal: The ~300-line `installGenesisEnvelope()` in `BridgeIdentityHandler.kt` reduces to a single JNI call. All orchestration (validation, silicon fingerprint, DBRW bootstrap, identity persistence) moves to Rust.

### Task 4.1: Define HostCommand proto messages

**Files:**
- Modify: `proto/dsm_app.proto`

**Step 1: Add messages**

```protobuf
// Rust → Kotlin: execute an OS-level action
message HostCommand {
  int32 command_id = 1;    // Correlation ID for response matching
  int32 kind = 2;          // HostCommandKind enum value
  bytes payload = 3;       // Command-specific protobuf payload
}

// Kotlin → Rust: result of OS-level action
message HostCommandResponse {
  int32 command_id = 1;    // Matches HostCommand.command_id
  bytes result = 2;        // Command-specific result bytes
  string error = 3;        // Empty if success
}

enum HostCommandKind {
  HOST_COMMAND_KIND_UNSPECIFIED = 0;
  HOST_COMMAND_KIND_SILICON_FINGERPRINT_ENROLL = 1;
  HOST_COMMAND_KIND_GET_HW_ANCHOR = 2;
  HOST_COMMAND_KIND_GENERATE_DBRW_SALT = 3;
}
```

Add `SDK_EVENT_KIND_HOST_COMMAND = 16` to the `SdkEventKind` enum.

**Step 2: Regenerate proto stubs**

Run: `pnpm --filter dsm-wallet run proto:gen && git diff`

**Step 3: Commit**

```bash
git add proto/dsm_app.proto
git commit -m "proto: add HostCommand/HostCommandResponse for Rust-driven OS actions"
```

---

### Task 4.2: Implement genesis orchestrator in Rust

**Files:**
- Create: `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/genesis_orchestrator.rs`
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/mod.rs`

**Step 1: Write the orchestrator**

This module:
1. Receives genesis envelope bytes from the frontend (via ingress)
2. Validates envelope structure (currently done in Kotlin's `parseGenesisEnvelopeInstallInput`)
3. Pushes `HostCommand::SiliconFingerprintEnroll` event, blocks on response channel
4. Pushes `HostCommand::GetHwAnchor` event, blocks on response channel
5. Calls internal DBRW bootstrap
6. Sets `has_identity(true)` and `sdk_ready(true)` (which auto-push session state per Phase 1)
7. Returns success/error

Use a `tokio::sync::oneshot` channel per command. Store pending channels in a `DashMap<i32, oneshot::Sender<HostCommandResponse>>`. New JNI function `host_command_response(bytes)` resolves the channel.

**Step 2: Write tests**

Test the orchestrator with mock host command responses (inject responses directly into the channel without going through JNI).

**Step 3: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/genesis_orchestrator.rs dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/mod.rs
git commit -m "feat: genesis orchestrator in Rust — validates, enrolls, bootstraps"
```

---

### Task 4.3: Add JNI entry point for host command responses

**Files:**
- Modify: `dsm_client/deterministic_state_machine/dsm_sdk/src/jni/unified_protobuf_bridge.rs`

**Step 1: Add JNI export**

```rust
#[no_mangle]
pub extern "system" fn Java_com_dsm_native_UnifiedNativeApi_hostCommandResponse(
    mut env: JNIEnv,
    _class: JClass,
    response_bytes: JByteArray,
) {
    let bytes = env.convert_byte_array(response_bytes).unwrap_or_default();
    crate::sdk::genesis_orchestrator::resolve_host_command(bytes);
}
```

**Step 2: Commit**

```bash
git add dsm_client/deterministic_state_machine/dsm_sdk/src/jni/unified_protobuf_bridge.rs
git commit -m "feat: JNI entry point for host command responses"
```

---

### Task 4.4: Kotlin host command executor

**Files:**
- Create: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/HostCommandExecutor.kt`

**Step 1: Implement command dispatcher**

```kotlin
object HostCommandExecutor {
    fun execute(commandBytes: ByteArray, context: Context) {
        val command = HostCommand.parseFrom(commandBytes)
        val result: ByteArray = when (command.kind) {
            HostCommandKind.HOST_COMMAND_KIND_SILICON_FINGERPRINT_ENROLL_VALUE ->
                SiliconFingerprint().enroll(context) // returns enrollment bytes
            HostCommandKind.HOST_COMMAND_KIND_GET_HW_ANCHOR_VALUE ->
                AntiCloneGate.getStableHwAnchorWithTrust(context).toByteArray()
            HostCommandKind.HOST_COMMAND_KIND_GENERATE_DBRW_SALT_VALUE ->
                SecureRandom().let { sr -> ByteArray(32).also { sr.nextBytes(it) } }
            else -> byteArrayOf()
        }
        val response = HostCommandResponse.newBuilder()
            .setCommandId(command.commandId)
            .setResult(ByteString.copyFrom(result))
            .build()
        UnifiedNativeApi.hostCommandResponse(response.toByteArray())
    }
}
```

**Step 2: Wire into event drain**

When `drainSdkEvents` returns events with `kind = HOST_COMMAND (16)`, call `HostCommandExecutor.execute(event.payload, context)`.

**Step 3: Build and verify**

Run: `cd dsm_client/android && ./gradlew assembleDebug`

**Step 4: Commit**

```bash
git add dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/HostCommandExecutor.kt
git commit -m "feat: Kotlin host command executor — dumb OS action proxy"
```

---

### Task 4.5: Gut `BridgeIdentityHandler.installGenesisEnvelope()`

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt`

**Step 1: Replace with single Rust call**

The ~300-line method reduces to:

```kotlin
fun installGenesisEnvelope(envelopeBytes: ByteArray): ByteArray {
    return UnifiedNativeApi.installGenesisEnvelope(envelopeBytes)
}
```

Rust's genesis orchestrator handles everything internally, using HostCommands for OS actions.

**Step 2: Remove dead code**

- Remove `parseGenesisEnvelopeInstallInput()`
- Remove `genesisLifecycleInFlight` / `genesisLifecycleInvalidated` atomics
- Remove silicon fingerprint / DBRW / identity persistence logic
- Remove `SharedPreferences` writes for identity data

**Step 3: Build and verify**

Run: `cd dsm_client/android && ./gradlew assembleDebug`

**Step 4: Commit**

```bash
git add dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt
git commit -m "refactor: gut BridgeIdentityHandler — all genesis logic now in Rust"
```

---

### Task 4.6: Gut `bootstrapFromPrefs()`

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeIdentityHandler.kt`

Same pattern as Task 4.5. Rust reads persisted identity from its own AppState storage. No SharedPreferences needed.

**Step 1: Replace with single Rust call**

```kotlin
fun bootstrapFromPrefs(): Boolean {
    return UnifiedNativeApi.bootstrapFromPersistedState()
}
```

**Step 2: Remove dead code** — all access level checks, salt loading, SDK context init, etc.

**Step 3: Commit**

```bash
git add dsm_client/android/
git commit -m "refactor: gut bootstrapFromPrefs — Rust handles cold-start bootstrap"
```

---

## Phase 5: Eliminate Remaining Protocol Logic from Kotlin

Goal: Remove protobuf parsing, validation, and routing decisions from remaining bridge handlers.

### Task 5.1: Remove protobuf parsing from `NativeBoundaryBridge.kt`

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/NativeBoundaryBridge.kt`

Remove `runBestEffortPostIngressHooks()` entirely (parses IngressRequest protobuf, branches on operation type). Move NFC capsule refresh trigger to Rust ingress handler.

**Step 1: Delete the method and all call sites**

**Step 2: In Rust `ingress.rs`, add NFC capsule refresh push after relevant operations**

**Step 3: Commit**

```bash
git add dsm_client/android/ dsm_client/deterministic_state_machine/
git commit -m "refactor: remove protobuf inspection from NativeBoundaryBridge"
```

---

### Task 5.2: Remove protobuf parsing from `BridgeBleHandler.kt`

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeBleHandler.kt`

Move `BleIdentityCharValue` parsing and field-size validation to Rust. Kotlin receives pre-validated bytes.

**Step 1: Add Rust-side validation in the BLE identity handler**

**Step 2: Kotlin receives validated genesis_hash + device_id as raw bytes from Rust**

**Step 3: Commit**

```bash
git add dsm_client/android/ dsm_client/deterministic_state_machine/
git commit -m "refactor: move BLE identity validation to Rust"
```

---

### Task 5.3: Remove special-case routing from `BridgeRouterHandler.kt`

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/BridgeRouterHandler.kt`

The `session.lock`/`session.unlock` special case (which triggered `publishCurrentSessionState`) was already removed in Phase 2. Verify the handler is now a pure pass-through: bytes in → JNI → bytes out.

**Step 1: Verify and clean up any remaining branching**

**Step 2: Commit**

```bash
git add dsm_client/android/
git commit -m "refactor: BridgeRouterHandler is now pure byte pass-through"
```

---

### Task 5.4: Remove business logic from `UnifiedCdbrwBridge.kt`

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/UnifiedCdbrwBridge.kt`

Silicon fingerprint enrollment, health tests, trust scoring — all move to Rust via HostCommand pattern from Phase 4.

**Step 1: Replace with Rust calls that use HostCommands for OS-level operations**

**Step 2: Commit**

```bash
git add dsm_client/android/ dsm_client/deterministic_state_machine/
git commit -m "refactor: move CDBRW logic to Rust — Kotlin only executes OS actions"
```

---

### Task 5.5: Simplify `SinglePathWebViewBridge.handleBinaryRpcInternal()`

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/bridge/SinglePathWebViewBridge.kt`

Reduce the 20+ case `when(method)` block. Most cases should become a single JNI call. Cases that need OS interaction (QR launch, BLE permissions) use the HostCommand pattern.

**Step 1: Audit each case — identify which are already pure pass-through**

**Step 2: Move remaining logic cases to Rust**

**Step 3: Commit**

```bash
git add dsm_client/android/ dsm_client/deterministic_state_machine/
git commit -m "refactor: simplify SinglePathWebViewBridge — most routing now in Rust"
```

---

### Task 5.6: Remove hardware state caching from `MainActivity.kt`

**Files:**
- Modify: `dsm_client/android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt`

Remove volatile fields: `qrScannerActive`, `batteryCharging`, `batteryLevelPercent`, `nfcReaderActive`, `isAppForeground`. Instead, Kotlin sends hardware facts to Rust on each lifecycle event (which it already does via `Unified.updateSessionHardwareFacts`). The cached fields are no longer needed since Kotlin no longer assembles the `SessionHardwareFactsProto` — Rust does.

Wait — Kotlin still needs to *build* the `SessionHardwareFactsProto` from Android APIs before sending it. The volatile fields serve as a cache so the proto can be assembled on any thread. This is transport-adjacent (collecting OS data for Rust). Keep the fields but ensure they're ONLY used for proto assembly, never for decision-making.

**Step 1: Audit each volatile field — confirm none are used in conditionals outside proto assembly**

**Step 2: Remove any that are used in logic decisions**

**Step 3: Commit**

```bash
git add dsm_client/android/
git commit -m "refactor: audit MainActivity state — ensure hardware cache is transport-only"
```

---

## Phase 6: Final Verification

### Task 6.1: Full build and test

**Step 1: Rust tests**

```bash
cd dsm_client/deterministic_state_machine && cargo test -p dsm_sdk -- --nocapture
```

**Step 2: Android build**

```bash
cd dsm_client/android && ./gradlew clean assembleDebug
```

**Step 3: NDK rebuild**

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

**Step 4: Symbol verification**

```bash
nm -gU dsm_client/android/app/src/main/jniLibs/arm64-v8a/libdsm_sdk.so | grep -c Java_
```

Expected: count should include new `hostCommandResponse` symbol.

### Task 6.2: On-device test — Genesis race condition

**Step 1:** Install on both test devices (A: R5CW620MQVL, B: RF8Y90PX5GN)
**Step 2:** Clear app data on both
**Step 3:** Tap INITIALIZE on both devices simultaneously
**Step 4:** Both should navigate to home screen (wallet_ready) every time
**Step 5:** Repeat 5 times to confirm determinism

### Task 6.3: On-device test — Session state transitions

**Step 1:** Background the app → should auto-lock if lock_on_pause enabled
**Step 2:** Foreground → should show lock screen
**Step 3:** Toggle BLE → hardware status should update in UI
**Step 4:** Battery change → should reflect in session state

---

## Critical Files Summary

| File | Phase | Action |
|------|-------|--------|
| `dsm_sdk/src/sdk/session_manager.rs` | 1 | Add `push_session_state_event()`, hook all mutations |
| `dsm_sdk/src/sdk/app_state.rs` | 1 | Hook `set_has_identity()` to push |
| `dsm_sdk/src/event.rs` | 3 | Add JNI notification in `push_event_bytes()` |
| `dsm_sdk/src/jni/jni_common.rs` | 3 | Add `notify_events_available()` |
| `dsm_sdk/src/sdk/genesis_orchestrator.rs` | 4 | New: Rust genesis orchestration |
| `dsm_sdk/src/jni/unified_protobuf_bridge.rs` | 4 | Add `hostCommandResponse` JNI export |
| `proto/dsm_app.proto` | 4 | Add HostCommand/HostCommandResponse messages |
| `android/.../MainActivity.kt` | 2 | Remove 22 publishSessionState calls |
| `android/.../BridgeIdentityHandler.kt` | 4 | Gut genesis orchestration (~300 lines) |
| `android/.../NativeBoundaryBridge.kt` | 2,5 | Remove protobuf inspection |
| `android/.../BridgeRouterHandler.kt` | 2 | Remove method-name branching |
| `android/.../NativeHostBridge.kt` | 2,5 | Remove session push + protobuf parsing |
| `android/.../BridgeBleHandler.kt` | 5 | Move validation to Rust |
| `android/.../UnifiedCdbrwBridge.kt` | 5 | Move CDBRW logic to Rust |
| `android/.../SinglePathWebViewBridge.kt` | 3,5 | Add event notification + simplify routing |
| `android/.../HostCommandExecutor.kt` | 4 | New: dumb OS action proxy |
| `frontend/src/dsm/NativeBoundaryBridge.ts` | 3 | Add immediate drain on signal |
