# DSM Architecture Issues

Identified during March 2026 code audit. Each section is one issue.

---

## 1. GOD OBJECT: `MainActivity.kt` (~1000+ lines)

**File:** `android/app/src/main/java/com/dsm/wallet/ui/MainActivity.kt`

**Problem:** Single class handles: WebView setup, binary MessagePort dispatch, NFC foreground dispatch + capsule writing, BLE coordinator lifecycle, biometric prompt, QR scanner launcher, system bar theming, runtime permission management, session state publishing, back navigation, genesis/enrollment thread dispatch, bridge executor pool, service binding, and CORS proxy.

**Impact:** Impossible for a new contributor to understand what MainActivity "is." Every Android concern routes through it. Bugs in NFC writing can be caused by changes to BLE service binding. Testing requires standing up the entire activity.

**Proposed split:**
- `NfcForegroundDispatcher` — owns `onNewIntent` NFC logic, foreground dispatch enable/disable
- `BridgePortHost` — owns `installDsmBinaryBridge`, `handleDsmPortMessage`, `dsmPort`, `pendingJsPort`
- `SessionPublisher` — owns `publishSessionState`, hardware facts collection
- `PermissionCoordinator` — owns all permission launchers (BT, camera) and result callbacks
- `SystemBarController` — owns `applySystemBarColors`, scrim management
- MainActivity becomes a thin lifecycle host that delegates to these components

**Labels:** `refactor`, `god-object`, `android`

---

## 2. GOD OBJECT: `unified_protobuf_bridge.rs` (~5700+ lines)

**File:** `dsm_sdk/src/jni/unified_protobuf_bridge.rs`

**Problem:** Every single JNI export for the entire SDK lives in one file. NFC capsule operations, Bitcoin operations, wallet operations, BLE operations, session management, recovery, diagnostics — all in one flat list of `#[no_mangle] pub extern "system" fn Java_...` functions.

**Impact:** Merge conflicts are guaranteed when two people touch different JNI features. Finding a specific export requires searching through thousands of lines. The file name implies "unified" is a design goal rather than a problem.

**Proposed split:** Group JNI exports by domain into separate files matching the existing JNI module structure (which already has `ble_bridge.rs`, `bootstrap.rs`, `identity.rs`, `wallet.rs` etc). Move each `Java_com_dsm_wallet_bridge_UnifiedNativeApi_*` function into the corresponding domain module. `UnifiedNativeApi.kt` on the Kotlin side can stay unified since it's just declarations.

**Labels:** `refactor`, `god-object`, `rust`, `jni`

---

## 3. GOD OBJECT: `BitcoinTapSdk` (~1400+ lines, growing)

**File:** `dsm_sdk/src/sdk/bitcoin_tap_sdk.rs`

**Problem:** One struct owns: all type definitions (VaultOperation, VaultDirection, VaultOpState, WithdrawalPlan, WithdrawalPlanLeg, WithdrawalBlockedVault, FractionalExitResult, DepositCompletion, DepositInitiation, VaultExecutionData, DbtcParams, etc), persistence (SQLite read/write/restore), vault advertisement publishing, storage node inventory sync, withdrawal planning/routing, deposit initiation/completion, DLV manager interaction, token metadata, and parameter resolution.

**Impact:** The type definitions are needed by callers but importing them means depending on the full SDK. Withdrawal planning logic is tangled with vault persistence. Can't test routing without a live DLV manager.

**Proposed split:**
- `bitcoin_tap_types.rs` — all public types, enums, structs (VaultOperation, WithdrawalPlan, DbtcParams, etc)
- `bitcoin_tap_persistence.rs` — SQLite persistence, `to_persisted_vault_record`, `persisted_to_vault_op`, `persist_vault`, `restore_from_persistence`
- `bitcoin_tap_advertisements.rs` — storage node vault publishing, inventory sync, `load_remote_vault_into_memory`
- `bitcoin_tap_withdrawal.rs` — withdrawal planning, routing, selector, `plan_withdrawal`
- `bitcoin_tap_sdk.rs` — slim orchestrator that composes the above

**Labels:** `refactor`, `god-object`, `rust`, `bitcoin`

---

## 4. GOD OBJECT: `bitcoin_invoke_routes.rs` (test infra mixed with production)

**File:** `dsm_sdk/src/handlers/bitcoin_invoke_routes.rs`

**Problem:** All `bitcoin.*` invoke routes in one file. More critically, ~200 lines of test infrastructure (`WithdrawalExecutionTestExpectation`, `WITHDRAWAL_EXECUTION_TEST_RESULTS` static, `set_withdrawal_execution_test_expectations`, `take_withdrawal_execution_test_result`, etc) are interleaved with production code behind `#[cfg(test)]`. The production `invoke_fractional_exit_internal` and `invoke_full_sweep_internal` methods contain `#[cfg(test)]` branches that intercept calls during testing.

**Impact:** Production code paths are conditional on test configuration. The file is hard to audit for correctness because test mocking and production logic are interleaved. Withdrawal execution, deposit completion, fractional exit, and full sweep all live in one `impl AppRouterImpl` block.

**Proposed fix:**
- Extract test harness into `bitcoin_invoke_routes_test_harness.rs`
- Split invoke handler into `bitcoin_deposit_routes.rs` and `bitcoin_withdrawal_routes.rs`
- Use trait-based mocking instead of `#[cfg(test)]` statics in production methods

**Labels:** `refactor`, `god-object`, `rust`, `testing`

---

## 5. NO PUBLIC SDK API SURFACE — Onboarding boundary missing

**Problem:** There is no clear boundary between "DSM platform" and "apps built on DSM." A developer who wants to build on DSM must understand the entire TS→Kotlin→Rust→JNI pipeline. The `dsmClient` namespace in TypeScript exposes internal implementation details (bridge methods, raw protobuf calls) rather than a clean API.

The current onboarding path for a new app developer is:
1. Read the TypeScript `dsm/` module source code
2. Trace `callBin()` through `WebViewBridge.ts` to understand the binary protocol
3. Read the Kotlin bridge to understand RPC routing
4. Read the Rust handler to understand what actually happens

There's no `dsm-sdk` npm package, no `DsmClient` interface, no getting-started guide.

**Impact:** Nobody outside the solo developer can build on DSM. Beta launch will have zero third-party adoption without a clean SDK boundary.

**Proposed fix:**
- Define a `DsmPublicApi` TypeScript interface that exposes high-level operations: `createWallet()`, `sendTokens()`, `getBalance()`, `depositBitcoin()`, `withdrawBitcoin()`, etc.
- Implement it as a facade over the existing bridge internals
- Document the API surface with JSDoc
- Keep all bridge/protobuf/binary framing details private
- Publish as `@dsm/sdk` or similar

**Labels:** `architecture`, `onboarding`, `sdk`, `high-priority`

---

## 6. DEAD CODE: `getNfcRingPassword` JNI export

**File:** `dsm_sdk/src/jni/unified_protobuf_bridge.rs`

**Problem:** The `Java_com_dsm_wallet_bridge_UnifiedNativeApi_getNfcRingPassword` JNI export was added for NFC tag password protection, then the feature was removed (passwords add friction to every automatic write). The Kotlin declaration in `UnifiedNativeApi.kt` was removed, but the Rust JNI export remains as dead code.

**Fix:** Delete the `getNfcRingPassword` function from `unified_protobuf_bridge.rs`.

**Labels:** `cleanup`, `dead-code`, `rust`

---

## 7. DEAD CODE: `activity_nfc_write.xml` layout file

**File:** `android/app/src/main/res/layout/activity_nfc_write.xml`

**Problem:** `NfcWriteActivity` uses a programmatic blank `View` (transparent surface, no UI). The XML layout file is never referenced and is left over from an earlier implementation.

**Fix:** Delete the file.

**Labels:** `cleanup`, `dead-code`, `android`

---

## 8. DUPLICATED SERIALIZATION: `capsule_to_bytes` vs core `encode_capsule`

**File:** `dsm_sdk/src/sdk/recovery_sdk.rs` (function `capsule_to_bytes`)
**Core:** `dsm/src/recovery/capsule.rs` (function `create_encrypted_capsule` internal serialization)

**Problem:** `create_capsule_from_current_state_with_cached_key()` in recovery_sdk.rs manually serializes a `RecoveryCapsule` to bytes using its own `capsule_to_bytes()` function. The core library's `create_encrypted_capsule` does the same serialization internally. If the core's format changes, the SDK's copy won't update, producing incompatible capsules.

**Impact:** Recovery capsules created by the cached-key path may not be decryptable by the core's `decrypt_recovery_capsule` if formats drift.

**Fix:** Either:
- Export the serialization function from core and use it in both places, or
- Add a `create_encrypted_capsule_with_key(key: &[u8; 32], capsule: &RecoveryCapsule)` to core that accepts a pre-derived key, eliminating the need for SDK-side serialization entirely

**Labels:** `bug-risk`, `rust`, `recovery`

---

## 9. DUPLICATE FILE: `BitcoinTapTab.tsx` exists in two locations

**Files:**
- `frontend/src/components/screens/BitcoinTapTab.tsx`
- `frontend/src/components/screens/bitcoin/BitcoinTapTab.tsx`

**Problem:** Two files with the same name in different directories. One is likely the original, the other the refactored version. Imports may reference either depending on when they were written.

**Fix:** Determine which is canonical, delete the other, update all imports.

**Labels:** `cleanup`, `dead-code`, `frontend`

---

## 10. `SinglePathWebViewBridge.kt` routes all RPC through a single dispatch

**File:** `android/app/src/main/java/com/dsm/wallet/bridge/SinglePathWebViewBridge.kt`

**Problem:** All RPC methods from the WebView are routed through `handleBinaryRpc(method, body)` which is a giant when/switch dispatching to various handlers. While some handlers have been extracted (`BridgeBleHandler`, `BridgeDiagnosticsHandler`, `BridgeIdentityHandler`, `BridgePreferencesHandler`, `BridgeRouterHandler`), the core dispatch is still a single function with 50+ method string matches.

**Impact:** Adding a new RPC method means modifying the central dispatch function. No compile-time guarantee that a method string matches a handler.

**Proposed fix:** Registry-based dispatch. Each handler module registers its method prefixes. The bridge iterates handlers until one claims the method. This is what `BridgeRouterHandler` partially does but it's not the universal pattern yet.

**Labels:** `refactor`, `android`, `bridge`

---

## 11. Frontend ↔ Rust contract is untyped

**Problem:** The TypeScript frontend communicates with Rust via `callBin(method: string, payload: Uint8Array)`. Method names are string literals scattered across the codebase. Payload is raw protobuf bytes. There's no compile-time check that the method exists, that the payload matches the expected proto message, or that the response is decoded correctly.

**Impact:** Typos in method strings cause silent failures. Proto schema changes break the frontend with no compiler error. Every call site has its own ad-hoc encode/decode logic.

**Proposed fix:**
- Generate TypeScript types from `.proto` files (protobuf-ts or similar)
- Create typed wrapper functions: `async function getBalance(): Promise<BalanceResponse>` that internally call `callBin("wallet.getBalance", ...)` and decode the response
- These wrappers become the public SDK surface (ties into issue #5)

**Labels:** `architecture`, `frontend`, `type-safety`

---

## 12. No integration test for NFC ring write → recovery flow

**Problem:** The NFC ring backup system spans three layers (TS → Kotlin → Rust) and involves capsule creation, NDEF formatting, NFC hardware write, and later capsule decryption for recovery. There is no end-to-end test that verifies a capsule created by `maybe_refresh_nfc_capsule` → serialized by `capsule_to_bytes` → written to a mock tag → read back → decrypted by `decrypt_recovery_capsule` produces the original state.

**Impact:** The duplicated serialization (issue #8) and the cached-key encryption path have no coverage. A format drift would only be caught on a real device during actual recovery.

**Fix:** Add a Rust integration test that: creates a capsule with `create_capsule_from_current_state_with_cached_key`, then decrypts it with `decrypt_recovery_capsule` (using the same derived key), and asserts the SMT root and counterparty tips match.

**Labels:** `testing`, `recovery`, `nfc`

---

## 13. Withdrawal UI may confuse users about fee deduction

**Problem:** The withdrawal plan response includes `gross_exit_sats`, `estimated_fee_sats`, and `estimated_net_sats` per leg. The dBTC burn is now correctly `requested_net_sats` (issue fixed in this session). However, the frontend may display these numbers in a way that confuses users about what happens:
- dBTC burned: 250,000 (what you give up on the DSM side)
- BTC received: ~245,300 (what arrives at your Bitcoin address)
- The ~4,700 difference is Bitcoin miner fees, not a DSM fee

If the UI shows "Fee: 4,700 sats" without context, users may think DSM is charging them.

**Fix:** Frontend should clearly label: "Bitcoin network fee (estimated): 4,700 sats" and show "You burn 250,000 dBTC → You receive ~245,300 BTC (after Bitcoin network fees)". The successor vault line should show "Remainder stays in vault: X sats (no fees deducted)".

**Labels:** `ux`, `frontend`, `bitcoin`

---

## 14. `AppRouterImpl` accumulates all handler methods via `impl` blocks

**File:** `dsm_sdk/src/handlers/app_router_impl.rs` + all `*_routes.rs` files

**Problem:** Every route handler file adds methods to `AppRouterImpl` via `impl AppRouterImpl { ... }` blocks. This means `AppRouterImpl` is the god struct — it owns references to `core_sdk`, `wallet`, `bitcoin_tap`, `bitcoin_keys`, `device_id_bytes`, and every other dependency. All handlers share all dependencies whether they need them or not.

**Impact:** Can't instantiate a handler in isolation for testing. Adding a new dependency to `AppRouterImpl` for one handler makes it available to all handlers. No dependency isolation.

**Proposed fix (long-term):** Trait-based handlers where each handler declares its own dependency set:
```rust
trait BitcoinHandler {
    fn bitcoin_tap(&self) -> &BitcoinTapSdk;
    fn bitcoin_keys(&self) -> &BitcoinKeyStore;
}
```
Short-term: document which fields each handler file actually uses.

**Labels:** `refactor`, `architecture`, `rust`

---

## 15. No `CONTRIBUTING.md` or architecture guide for new developers

**Problem:** The project has a `.claude/` skills directory for AI assistants but no human-readable architecture guide. A new developer has no map of: which crate does what, how the three layers communicate, where to add a new feature, what the testing strategy is, or what the invariants are.

**Impact:** Solo-developer bus factor. Beta launch with investor interest means eventual team growth, and onboarding will be painful.

**Fix:** Create `docs/ARCHITECTURE.md` covering:
- Layer diagram (TS → Kotlin → Rust → Core)
- Communication protocol (MessagePort binary, protobuf envelopes)
- Key invariants (Rust owns crypto, Kotlin is transport-only, TS is UI-only)
- File map (which directory owns which domain)
- How to add a new RPC route end-to-end
- How to run tests

**Labels:** `documentation`, `onboarding`, `high-priority`
